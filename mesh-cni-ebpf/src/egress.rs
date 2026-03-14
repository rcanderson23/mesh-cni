use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::bpf_ktime_get_ns,
    maps::lpm_trie::Key as LpmKey,
    programs::TcContext,
};
use aya_log_ebpf::{error, warn};
use mesh_cni_ebpf_common::{
    KubeProtocol,
    conntrack::{ConntrackValue, TcpFlags},
    policy::{Action, PolicyDirection, WORLD_ID},
    service::NodePortRevNatV4Key,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    sctp::SctpHdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::{
    CONNTRACK_V4, NODEPORT_REV_NAT_V4, id_v4,
    policy::{check_cidr_policy_v4, check_identity_policy, conntrack_hit, conntrack_keys},
};

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

    let src_ip = u32::from_be_bytes(ipv4hdr.src_addr);
    let dst_ip = u32::from_be_bytes(ipv4hdr.dst_addr);

    let (proto, src_port, dst_port, should_insert, tcp_flags) = match ipv4hdr.proto {
        network_types::ip::IpProto::Tcp => {
            let tcphdr: TcpHdr = ctx
                .load(EthHdr::LEN + ipv4hdr.ihl() as usize)
                .map_err(|_| TC_ACT_PIPE)?;
            let syn = tcphdr.syn() == 1;
            let ack = tcphdr.ack() == 1;
            let fin = tcphdr.fin() == 1;
            let rst = tcphdr.rst() == 1;
            (
                KubeProtocol::Tcp,
                u16::from_be_bytes(tcphdr.source),
                u16::from_be_bytes(tcphdr.dest),
                syn && !ack,
                Some(TcpFlags { syn, ack, fin, rst }),
            )
        }
        network_types::ip::IpProto::Udp => {
            let udphdr: UdpHdr = ctx
                .load(EthHdr::LEN + ipv4hdr.ihl() as usize)
                .map_err(|_| TC_ACT_PIPE)?;
            (
                KubeProtocol::Udp,
                u16::from_be_bytes(udphdr.src),
                u16::from_be_bytes(udphdr.dst),
                true,
                None,
            )
        }
        network_types::ip::IpProto::Sctp => {
            let sctphdr: SctpHdr = ctx
                .load(EthHdr::LEN + ipv4hdr.ihl() as usize)
                .map_err(|_| TC_ACT_PIPE)?;
            (
                KubeProtocol::Sctp,
                u16::from_be_bytes(sctphdr.src),
                u16::from_be_bytes(sctphdr.dst),
                true,
                None,
            )
        }
        _ => return Ok(TC_ACT_PIPE),
    };

    // Let NodePort reply traffic pass policy/identity checks on this hook.
    // It will be redirected by pod-veth egress and reverse-NATed on mesh_pod ingress.
    let rev_nat_key =
        NodePortRevNatV4Key::new_egress(src_ip, dst_ip, src_port, dst_port, proto as u8);
    if unsafe { NODEPORT_REV_NAT_V4.get(rev_nat_key) }.is_some() {
        return Ok(TC_ACT_PIPE);
    }

    // LpmTrie expects big endian order for comparisons.
    // Local endpoint identity must exist; unresolved peer identity is treated as world.
    let Some(src_id) = id_v4(LpmKey::new(32, src_ip.to_be())) else {
        warn!(
            &ctx,
            "dropping egress packet with unknown src identity src_ip: {}; dst_ip: {}",
            Ipv4Addr::from_bits(src_ip),
            Ipv4Addr::from_bits(src_ip),
        );
        return Ok(TC_ACT_SHOT);
    };
    let dst_id = id_v4(LpmKey::new(32, dst_ip.to_be())).unwrap_or(WORLD_ID);
    let (ct_key, ct_rev) = conntrack_keys(src_ip, dst_ip, src_port, dst_port, proto, src_id);

    let now = unsafe { bpf_ktime_get_ns() };
    if conntrack_hit(&ctx, ct_key, ct_rev, now, proto, tcp_flags) {
        return Ok(TC_ACT_PIPE);
    }

    if check_identity_policy(src_id, dst_id, dst_port, proto, PolicyDirection::Egress)
        == Action::Deny
        && check_cidr_policy_v4(src_id, dst_ip, dst_port, proto, PolicyDirection::Egress)
            == Action::Deny
    {
        warn!(
            &ctx,
            "denied src: {}:{}; dst: {}:{}; proto: {}",
            src_id,
            src_port,
            dst_id,
            dst_port,
            proto as u8
        );
        return Ok(TC_ACT_SHOT);
    }
    if should_insert
        && src_ip != dst_ip
        && let Err(e) = CONNTRACK_V4.insert(
            ct_key,
            ConntrackValue::from_packet(proto, now, tcp_flags),
            0,
        )
    {
        error!(&ctx, "failed to insert into conntrack: {}", e);
    }
    Ok(TC_ACT_PIPE)
}
