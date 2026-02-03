use aya_ebpf::{
    bindings::TC_ACT_PIPE, helpers::bpf_ktime_get_ns, maps::lpm_trie::Key as LpmKey,
    programs::TcContext,
};
use aya_log_ebpf::info;
use mesh_cni_ebpf_common::{
    conntrack::{ConntrackKeyV4, ConntrackValue},
    policy::{
        ANY_ID, ANY_PORT, Action, PolicyDirection, PolicyIndexKey, PolicyProtocol, PolicyRuleKey,
        PolicyValue, RULESET_NONE,
    },
};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr, udp::UdpHdr};

use crate::{CONNTRACK_V4, POLICY_INDEX, POLICY_RULESET, id_v4};

#[inline]
pub fn handle_ipv4(ctx: TcContext, direction: PolicyDirection) -> Result<i32, i32> {
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
    };
    let ct_rev = ConntrackKeyV4 {
        src_ip: dst,
        dst_ip: src,
        src_port: dst_port,
        dst_port: src_port,
        proto,
        _pad: [0; 3],
    };

    let now = unsafe { bpf_ktime_get_ns() };
    if unsafe { CONNTRACK_V4.get(ct_key) }.is_some() {
        let _ = CONNTRACK_V4.insert(ct_key, ConntrackValue { last_seen_ns: now }, 0);
        return Ok(TC_ACT_PIPE);
    }
    if unsafe { CONNTRACK_V4.get(ct_rev) }.is_some() {
        let _ = CONNTRACK_V4.insert(ct_rev, ConntrackValue { last_seen_ns: now }, 0);
        return Ok(TC_ACT_PIPE);
    }

    if should_insert {
        let _ = CONNTRACK_V4.insert(ct_key, ConntrackValue { last_seen_ns: now }, 0);
    }

    let mut action: u8 = Action::Allow.into();
    let mut ruleset_id = RULESET_NONE;

    let direction: u8 = direction.into();
    let idx_candidates = [
        PolicyIndexKey {
            src_id,
            dst_id,
            direction,
            _pad: [0; 3],
        },
        PolicyIndexKey {
            src_id,
            dst_id,
            direction: PolicyDirection::Any.into(),
            _pad: [0; 3],
        },
        PolicyIndexKey {
            src_id: ANY_ID,
            dst_id,
            direction,
            _pad: [0; 3],
        },
        PolicyIndexKey {
            src_id: ANY_ID,
            dst_id,
            direction: PolicyDirection::Any.into(),
            _pad: [0; 3],
        },
        PolicyIndexKey {
            src_id,
            dst_id: ANY_ID,
            direction,
            _pad: [0; 3],
        },
        PolicyIndexKey {
            src_id,
            dst_id: ANY_ID,
            direction: PolicyDirection::Any.into(),
            _pad: [0; 3],
        },
    ];

    let mut found_index = false;
    for idx_key in idx_candidates {
        if let Some(id) = unsafe { POLICY_INDEX.get(idx_key) } {
            ruleset_id = *id;
            found_index = true;
            break;
        }
    }

    if found_index {
        if ruleset_id == RULESET_NONE {
            action = Action::Deny.into();
        } else {
            let rule_candidates = [
                PolicyRuleKey {
                    ruleset_id,
                    proto,
                    _pad0: [0; 3],
                    port: dst_port,
                    _pad1: [0; 2],
                },
                PolicyRuleKey {
                    ruleset_id,
                    proto,
                    _pad0: [0; 3],
                    port: ANY_PORT,
                    _pad1: [0; 2],
                },
                PolicyRuleKey {
                    ruleset_id,
                    proto: PolicyProtocol::Any.into(),
                    _pad0: [0; 3],
                    port: ANY_PORT,
                    _pad1: [0; 2],
                },
            ];

            let mut matched = false;
            for rule_key in rule_candidates {
                if let Some(PolicyValue {
                    action: rule_action,
                }) = unsafe { POLICY_RULESET.get(rule_key) }
                {
                    action = *rule_action;
                    matched = true;
                    break;
                }
            }

            if !matched {
                action = Action::Deny.into();
            }
        }
    }

    info!(
        &ctx,
        "L4: src: {}:{}; dst: {}:{}; ruleset: {}; action: {}",
        src_id,
        src_port,
        dst_id,
        dst_port,
        ruleset_id,
        action,
    );
    Ok(TC_ACT_PIPE)
}
