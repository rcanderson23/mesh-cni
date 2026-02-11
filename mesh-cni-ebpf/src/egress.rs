use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::bpf_ktime_get_ns,
    maps::lpm_trie::Key as LpmKey,
    programs::TcContext,
};
use aya_log_ebpf::{error, warn};
use mesh_cni_ebpf_common::{
    conntrack::ConntrackValue,
    policy::{Action, PolicyDirection, WORLD_ID},
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    sctp::SctpHdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::{
    CONNTRACK_V4, id_v4,
    policy::{check_policy, conntrack_hit, conntrack_keys},
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
        network_types::ip::IpProto::Sctp => {
            let sctphdr: SctpHdr = ctx
                .load(EthHdr::LEN + Ipv4Hdr::LEN)
                .map_err(|_| TC_ACT_PIPE)?;
            (
                ipv4hdr.proto as u8,
                u16::from_be_bytes(sctphdr.src),
                u16::from_be_bytes(sctphdr.dst),
                true,
            )
        }
        _ => return Ok(TC_ACT_PIPE),
    };

    let (ct_key, ct_rev) = conntrack_keys(src_ip, dst_ip, src_port, dst_port, proto, src_id);

    let now = unsafe { bpf_ktime_get_ns() };
    if conntrack_hit(&ctx, ct_key, ct_rev, now) {
        return Ok(TC_ACT_PIPE);
    }

    if check_policy(src_id, dst_id, dst_port, proto, PolicyDirection::Egress) == Action::Deny {
        warn!(
            &ctx,
            "denied src: {}:{}; dst: {}:{}; proto: {}", src_id, src_port, dst_id, dst_port, proto
        );
        return Ok(TC_ACT_SHOT);
    }
    if should_insert
        && src_ip != dst_ip
        && let Err(e) = CONNTRACK_V4.insert(ct_key, ConntrackValue { last_seen_ns: now }, 0)
    {
        error!(&ctx, "failed to insert into conntrack: {}", e);
    }
    Ok(TC_ACT_PIPE)
}
