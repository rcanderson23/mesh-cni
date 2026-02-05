use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::bpf_ktime_get_ns,
    maps::lpm_trie::Key as LpmKey,
    programs::TcContext,
};
use aya_log_ebpf::{error, info, warn};
use mesh_cni_ebpf_common::{
    conntrack::{ConntrackKeyV4, ConntrackValue},
    policy::{Action, PolicyDirection},
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::{CONNTRACK_V4, id_v4, policy::check_policy};

#[inline]
pub fn try_mesh_cni_egress(ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;

    let Ok(ether_type) = ethhdr.ether_type() else {
        return Ok(TC_ACT_PIPE);
    };

    // TODO: handle ipv6
    if !matches!(ether_type, EtherType::Ipv4) {
        return Ok(TC_ACT_PIPE);
    }

    handle_ipv4(ctx)
}

#[inline]
fn handle_ipv4(ctx: TcContext) -> Result<i32, i32> {
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| TC_ACT_PIPE)?;

    let src = u32::from_be_bytes(ipv4hdr.src_addr);
    let dst = u32::from_be_bytes(ipv4hdr.dst_addr);

    // LpmTrie expects big endian order for comparisons
    let (Some(src_id), Some(dst_id)) = (
        id_v4(LpmKey::new(32, src.to_be())),
        id_v4(LpmKey::new(32, dst.to_be())),
    ) else {
        return Ok(TC_ACT_PIPE);
    };

    let (proto, src_port, dst_port, should_insert) = match ipv4hdr.proto {
        network_types::ip::IpProto::Tcp => {
            let tcphdr: TcpHdr = ctx
                .load(EthHdr::LEN + Ipv4Hdr::LEN)
                .map_err(|_| TC_ACT_PIPE)?;
            let syn = tcphdr.syn() == 1;
            let ack = tcphdr.ack() == 1;
            (
                ipv4hdr.proto as u8,
                u16::from_be_bytes(tcphdr.source),
                u16::from_be_bytes(tcphdr.dest),
                syn && !ack,
            )
        }
        network_types::ip::IpProto::Udp => {
            let udphdr: UdpHdr = ctx
                .load(EthHdr::LEN + Ipv4Hdr::LEN)
                .map_err(|_| TC_ACT_PIPE)?;
            (
                ipv4hdr.proto as u8,
                u16::from_be_bytes(udphdr.src),
                u16::from_be_bytes(udphdr.dst),
                true,
            )
        }
        network_types::ip::IpProto::Sctp => return Ok(TC_ACT_PIPE),
        _ => return Ok(TC_ACT_PIPE),
    };

    let ct_key = ConntrackKeyV4 {
        src_ip: src,
        dst_ip: dst,
        src_port,
        dst_port,
        proto,
        _pad: [0; 3],
        initiator_id: src_id,
    };
    let ct_rev = ConntrackKeyV4 {
        src_ip: dst,
        dst_ip: src,
        src_port: dst_port,
        dst_port: src_port,
        proto,
        _pad: [0; 3],
        initiator_id: src_id,
    };

    let now = unsafe { bpf_ktime_get_ns() };
    if unsafe { CONNTRACK_V4.get(ct_key) }.is_some() {
        if CONNTRACK_V4
            .insert(ct_key, ConntrackValue { last_seen_ns: now }, 0)
            .is_err()
        {
            error!(&ctx, "failed to insert into conntrack");
        };
        return Ok(TC_ACT_PIPE);
    }
    if unsafe { CONNTRACK_V4.get(ct_rev) }.is_some() {
        if CONNTRACK_V4
            .insert(ct_rev, ConntrackValue { last_seen_ns: now }, 0)
            .is_err()
        {
            error!(&ctx, "failed to insert into conntrack");
        };
        return Ok(TC_ACT_PIPE);
    }

    if check_policy(src_id, dst_id, dst_port, proto, PolicyDirection::Ingress) == Action::Deny {
        info!(
            &ctx,
            "denying traffic src: {}:{} dst: {}:{}", src_id, src_port, dst_id, dst_port
        );
        return Ok(TC_ACT_SHOT);
    }
    if should_insert {
        if CONNTRACK_V4
            .insert(ct_key, ConntrackValue { last_seen_ns: now }, 0)
            .is_err()
        {
            error!(&ctx, "failed to insert into conntrack");
        }
    }
    Ok(TC_ACT_PIPE)
}
