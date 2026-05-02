use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::tcx_action_base::{TCX_DROP, TCX_NEXT, TCX_PASS},
    helpers::bpf_ktime_get_ns,
    maps::lpm_trie::Key as LpmKey,
    programs::TcContext,
};
use aya_log_ebpf::{error, warn};
use mesh_cni_ebpf_common::{
    KubeProtocol,
    conntrack::ConntrackValue,
    fragment::{FragmentKeyV4, FragmentValue},
    policy::{Action, PolicyDirection, WORLD_ID},
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

use crate::{
    CONNTRACK_V4, FRAGMENT_V4,
    fragment::is_first_frag_v4,
    id_v4,
    l4::l4_header_check,
    policy::{check_cidr_policy_v4, check_identity_policy, conntrack_hit, conntrack_keys},
};

#[inline]
pub fn try_mesh_cni_ingress(ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TCX_PASS)?;

    let Ok(ether_type) = ethhdr.ether_type() else {
        return Ok(TCX_PASS);
    };

    // TODO: handle ipv6
    if !matches!(ether_type, EtherType::Ipv4) {
        return Ok(TCX_PASS);
    }

    handle_ipv4(ctx)
}

#[inline]
fn handle_ipv4(ctx: TcContext) -> Result<i32, i32> {
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| TCX_PASS)?;

    let src_ip = u32::from_be_bytes(ipv4hdr.src_addr);
    let dst_ip = u32::from_be_bytes(ipv4hdr.dst_addr);

    // LpmTrie expects big endian order for comparisons.
    // Local endpoint identity must exist; unresolved peer identity is treated as world.
    let src_id = id_v4(LpmKey::new(32, src_ip.to_be())).unwrap_or(WORLD_ID);
    let Some(dst_id) = id_v4(LpmKey::new(32, dst_ip.to_be())) else {
        warn!(
            &ctx,
            "dropping ingress packet with unknown dst identity src_ip: {}; dst_ip: {}",
            Ipv4Addr::from_bits(src_ip),
            Ipv4Addr::from_bits(dst_ip),
        );
        return Ok(TCX_DROP);
    };

    let Ok(proto) = KubeProtocol::try_from(ipv4hdr.proto) else {
        return Ok(TCX_PASS);
    };

    let l4_check = l4_header_check(&ctx, &ipv4hdr)?;
    let src_port = l4_check.src_port;
    let dst_port = l4_check.dst_port;
    let tcp_flags = l4_check.tcp_flags();

    if is_first_frag_v4(&ipv4hdr) {
        let key = FragmentKeyV4::new(src_ip, dst_ip, ipv4hdr.id(), proto as u8);
        let now = unsafe { bpf_ktime_get_ns() };
        let value = FragmentValue::new(src_port, dst_port, now);
        FRAGMENT_V4.insert(key, value, 0).map_err(|_| TCX_DROP)?;
    }

    let (ct_key, ct_rev) = conntrack_keys(src_ip, dst_ip, src_port, dst_port, proto, dst_id);

    let now = unsafe { bpf_ktime_get_ns() };
    if conntrack_hit(&ctx, ct_key, ct_rev, now, proto, tcp_flags) {
        return Ok(TCX_NEXT);
    }
    if check_identity_policy(src_id, dst_id, dst_port, proto, PolicyDirection::Ingress)
        == Action::Deny
        && check_cidr_policy_v4(dst_id, src_ip, dst_port, proto, PolicyDirection::Ingress)
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
        return Ok(TCX_DROP);
    }

    if l4_check.should_insert()
        && src_ip != dst_ip
        && let Err(e) = CONNTRACK_V4.insert(
            ct_key,
            ConntrackValue::from_packet(proto, now, tcp_flags),
            0,
        )
    {
        error!(&ctx, "failed to insert into conntrack: {}", e);
    }
    Ok(TCX_NEXT)
}
