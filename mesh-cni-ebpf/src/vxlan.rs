use aya_ebpf::{
    bindings::{
        BPF_F_ADJ_ROOM_DECAP_L3_IPV4, BPF_F_ADJ_ROOM_FIXED_GSO, TC_ACT_PIPE, TC_ACT_SHOT,
        bpf_adj_room_mode::BPF_ADJ_ROOM_MAC, bpf_tunnel_key,
    },
    helpers::generated::{bpf_redirect, bpf_redirect_peer, bpf_skb_set_tunnel_key},
    maps::lpm_trie::Key as LpmKey,
    programs::TcContext,
};
use aya_log_ebpf::{error, warn};
use mesh_cni_ebpf_common::route::RouteType;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
    vxlan::VxlanHdr,
};

use crate::ROUTER_V4;

const VXLAN_I_FLAG: u8 = 0x08;
const VXLAN_PORT: u16 = 4789;

// TODO: implement ipv6
#[inline]
pub fn try_mesh_cni_vxlan_veth_egress(ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;
    let Ok(ether_type) = ethhdr.ether_type() else {
        return Ok(TC_ACT_PIPE);
    };
    if !matches!(ether_type, EtherType::Ipv4) {
        return Ok(TC_ACT_PIPE);
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| TC_ACT_PIPE)?;
    let dst_ip = u32::from_be_bytes(ipv4hdr.dst_addr);

    let Some(remote) = ROUTER_V4.get(LpmKey::new(32, dst_ip.to_be())).copied() else {
        return Ok(TC_ACT_PIPE);
    };

    if remote.route_type != RouteType::RemotePod as u8 {
        return Ok(TC_ACT_PIPE);
    }

    let mut key = bpf_tunnel_key {
        tunnel_id: remote.vni,
        __bindgen_anon_1: aya_ebpf::bindings::bpf_tunnel_key__bindgen_ty_1 {
            remote_ipv4: remote.remote_ip,
        },
        tunnel_tos: 0,
        tunnel_ttl: 64,
        __bindgen_anon_2: aya_ebpf::bindings::bpf_tunnel_key__bindgen_ty_2 { tunnel_flags: 0 },
        tunnel_label: 0,
        __bindgen_anon_3: aya_ebpf::bindings::bpf_tunnel_key__bindgen_ty_3 { local_ipv4: 0 },
    };
    match unsafe {
        bpf_skb_set_tunnel_key(
            ctx.skb.skb,
            &mut key,
            core::mem::size_of::<bpf_tunnel_key>() as u32,
            0,
        )
    } {
        rc if rc < 0 => {
            error!(&ctx, "failed to set tunnel, got {}", rc);
            Err(TC_ACT_SHOT)
        }
        _ => match unsafe { bpf_redirect(remote.ifindex, 0) } {
            rc if rc < 0 => {
                error!(&ctx, "failed to redirect packet, got {}", rc);
                Err(TC_ACT_SHOT)
            }
            rc => Ok(rc as i32),
        },
    }
}

// TODO: implement ipv6
#[inline]
pub fn try_mesh_cni_vxlan_node_ingress(ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;
    let Ok(ether_type) = ethhdr.ether_type() else {
        return Ok(TC_ACT_PIPE);
    };
    if !matches!(ether_type, EtherType::Ipv4) {
        return Ok(TC_ACT_PIPE);
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| TC_ACT_PIPE)?;
    if !matches!(ipv4hdr.proto, IpProto::Udp) {
        return Ok(TC_ACT_PIPE);
    }

    let ihl = ipv4hdr.ihl() as usize;
    let udp_offset = EthHdr::LEN + ihl;
    let udphdr: UdpHdr = ctx.load(udp_offset).map_err(|_| TC_ACT_PIPE)?;
    let dst_port = u16::from_be_bytes(udphdr.dst);
    if dst_port != VXLAN_PORT {
        return Ok(TC_ACT_PIPE);
    }

    let vxlan_offset = udp_offset + UdpHdr::LEN;
    let vxlanhdr: VxlanHdr = ctx.load(vxlan_offset).map_err(|_| TC_ACT_PIPE)?;
    if (vxlanhdr.flags & VXLAN_I_FLAG) == 0 {
        warn!(&ctx, "dropping vxlan packet without valid I flag");
        return Ok(TC_ACT_SHOT);
    }

    if vxlanhdr.vni() != 1 {
        return Ok(TC_ACT_SHOT);
    }

    let remove_len = ihl + UdpHdr::LEN + VxlanHdr::LEN + EthHdr::LEN;
    ctx.adjust_room(
        -(remove_len as i32),
        BPF_ADJ_ROOM_MAC,
        (BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_DECAP_L3_IPV4) as u64,
    )
    .map_err(|e| {
        error!(&ctx, "failed to decapsulate vxlan packet, got {}", e);
        TC_ACT_SHOT
    })?;

    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;
    let Ok(ether_type) = ethhdr.ether_type() else {
        return Ok(TC_ACT_PIPE);
    };
    if !matches!(ether_type, EtherType::Ipv4) {
        return Ok(TC_ACT_PIPE);
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| TC_ACT_PIPE)?;
    let dst_ip = u32::from_be_bytes(ipv4hdr.dst_addr);

    let Some(remote) = ROUTER_V4.get(LpmKey::new(32, dst_ip.to_be())).copied() else {
        return Ok(TC_ACT_PIPE);
    };

    if remote.route_type != RouteType::LocalPod as u8 {
        error!(&ctx, "dropping packet for pod not on this node");
        return Err(TC_ACT_SHOT);
    }

    match unsafe { bpf_redirect_peer(remote.ifindex, 0) } {
        rc if rc < 0 => {
            error!(&ctx, "failed to set tunnel, got {}", rc);
            Err(TC_ACT_SHOT)
        }
        rc => Ok(rc as i32),
    }
}

// TODO: implement ipv6
#[inline]
pub fn try_mesh_cni_host_router_egress(ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;
    let Ok(ether_type) = ethhdr.ether_type() else {
        return Ok(TC_ACT_PIPE);
    };
    if !matches!(ether_type, EtherType::Ipv4) {
        return Ok(TC_ACT_PIPE);
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| TC_ACT_PIPE)?;
    let dst_ip = u32::from_be_bytes(ipv4hdr.dst_addr);

    let Some(remote) = ROUTER_V4.get(LpmKey::new(32, dst_ip.to_be())).copied() else {
        return Ok(TC_ACT_PIPE);
    };

    match remote.route_type {
        x if x == RouteType::LocalPod as u8 => match unsafe { bpf_redirect(remote.ifindex, 0) } {
            rc if rc < 0 => {
                error!(&ctx, "failed to redirect local packet, got {}", rc);
                Err(TC_ACT_SHOT)
            }
            rc => Ok(rc as i32),
        },
        x if x == RouteType::RemotePod as u8 => {
            let mut key = bpf_tunnel_key {
                tunnel_id: remote.vni,
                __bindgen_anon_1: aya_ebpf::bindings::bpf_tunnel_key__bindgen_ty_1 {
                    remote_ipv4: remote.remote_ip,
                },
                tunnel_tos: 0,
                tunnel_ttl: 64,
                __bindgen_anon_2: aya_ebpf::bindings::bpf_tunnel_key__bindgen_ty_2 {
                    tunnel_flags: 0,
                },
                tunnel_label: 0,
                __bindgen_anon_3: aya_ebpf::bindings::bpf_tunnel_key__bindgen_ty_3 {
                    local_ipv4: 0,
                },
            };
            match unsafe {
                bpf_skb_set_tunnel_key(
                    ctx.skb.skb,
                    &mut key,
                    core::mem::size_of::<bpf_tunnel_key>() as u32,
                    0,
                )
            } {
                rc if rc < 0 => {
                    error!(&ctx, "failed to set tunnel, got {}", rc);
                    Err(TC_ACT_SHOT)
                }
                _ => match unsafe { bpf_redirect(remote.ifindex, 0) } {
                    rc if rc < 0 => {
                        error!(&ctx, "failed to redirect packet, got {}", rc);
                        Err(TC_ACT_SHOT)
                    }
                    rc => Ok(rc as i32),
                },
            }
        }
        unknown => {
            error!(&ctx, "unknown route type {}", unknown);
            Err(TC_ACT_SHOT)
        }
    }
}
