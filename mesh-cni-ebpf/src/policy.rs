use aya_ebpf::{maps::lpm_trie::Key as LpmKey, programs::TcContext};
use aya_log_ebpf::error;
use mesh_cni_ebpf_common::{
    IdentityId, KubeProtocol,
    conntrack::{
        CT_TIMEOUT_TCP_ESTABLISHED_NS, CT_TIMEOUT_TCP_FIN_NS, CT_TIMEOUT_TCP_RST_NS,
        CT_TIMEOUT_TCP_SYN_NS, CT_TIMEOUT_UDP_NS, ConntrackKeyV4, ConntrackValue, TcpFlags,
        TcpState,
    },
    policy::{
        ANY_ID, ANY_PORT, Action, CidrPolicyMapDataV4, PolicyDirection, PolicyIndexKey,
        PolicyProtocol, PolicyRuleKey, RULESET_NONE, RulesetId,
    },
};

use crate::{CONNTRACK_V4, POLICY_CIDR_V4, POLICY_INDEX, POLICY_RULESET};

#[inline(always)]
pub(crate) fn conntrack_hit(
    ctx: &TcContext,
    ct_key: ConntrackKeyV4,
    ct_rev: ConntrackKeyV4,
    now: u64,
    proto: KubeProtocol,
    tcp_flags: Option<TcpFlags>,
) -> bool {
    if let Some(value) = unsafe { CONNTRACK_V4.get(ct_key) } {
        if is_conntrack_expired(*value, now, proto) {
            if CONNTRACK_V4.remove(ct_key).is_err() {
                error!(ctx, "failed to remove expired conntrack key");
            };
        } else {
            let new_value = next_conntrack_value(*value, now, proto, tcp_flags, false);
            if CONNTRACK_V4.insert(ct_key, new_value, 0).is_err() {
                error!(ctx, "failed to insert into conntrack");
            };
            return true;
        }
    }
    if let Some(value) = unsafe { CONNTRACK_V4.get(ct_rev) } {
        if is_conntrack_expired(*value, now, proto) {
            if CONNTRACK_V4.remove(ct_rev).is_err() {
                error!(ctx, "failed to remove expired conntrack reverse key");
            };
        } else {
            let new_value = next_conntrack_value(*value, now, proto, tcp_flags, true);
            if CONNTRACK_V4.insert(ct_rev, new_value, 0).is_err() {
                error!(ctx, "failed to insert into conntrack");
            };
            return true;
        }
    }
    false
}

#[inline(always)]
fn next_conntrack_value(
    current: ConntrackValue,
    now: u64,
    proto: KubeProtocol,
    tcp_flags: Option<TcpFlags>,
    is_reply: bool,
) -> ConntrackValue {
    let next_state = if tcp_flags.is_none() && proto == KubeProtocol::Tcp {
        current.tcp_state()
    } else {
        current
            .tcp_state()
            .advance(TcpState::from_packet(proto, tcp_flags, is_reply))
    };
    ConntrackValue::new(now, next_state)
}

#[inline(always)]
fn is_conntrack_expired(value: ConntrackValue, now: u64, proto: KubeProtocol) -> bool {
    let timeout = match proto {
        KubeProtocol::Tcp => match value.tcp_state() {
            TcpState::Syn => CT_TIMEOUT_TCP_SYN_NS,
            TcpState::Established => CT_TIMEOUT_TCP_ESTABLISHED_NS,
            TcpState::FinInitiator | TcpState::FinResponder => CT_TIMEOUT_TCP_ESTABLISHED_NS,
            TcpState::Closed => CT_TIMEOUT_TCP_FIN_NS,
            TcpState::Rst => CT_TIMEOUT_TCP_RST_NS,
            _ => CT_TIMEOUT_TCP_SYN_NS,
        },
        _ => CT_TIMEOUT_UDP_NS,
    };
    now.saturating_sub(value.last_seen_ns) > timeout
}

#[inline]
/// Generates the conntrack keys to be checked.
/// IPs and ports are expected to be in host order
pub(crate) fn conntrack_keys(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: KubeProtocol,
    initiator_id: IdentityId,
) -> (ConntrackKeyV4, ConntrackKeyV4) {
    (
        ConntrackKeyV4 {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto: proto as u8,
            _pad: [0; 3],
            initiator_id,
        },
        ConntrackKeyV4 {
            src_ip: dst_ip,
            dst_ip: src_ip,
            src_port: dst_port,
            dst_port: src_port,
            proto: proto as u8,
            _pad: [0; 3],
            initiator_id,
        },
    )
}

#[inline]
/// Checks identity policy.
/// dst_port is expected to be in host order
pub(crate) fn check_identity_policy(
    src_id: IdentityId,
    dst_id: IdentityId,
    dst_port: u16,
    proto: KubeProtocol,
    direction: PolicyDirection,
) -> Action {
    let direction_u8: u8 = direction.into();
    let idx_candidates = [
        PolicyIndexKey {
            src_id,
            dst_id,
            direction: direction_u8,
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
            direction: direction_u8,
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
            direction: direction_u8,
            _pad: [0; 3],
        },
        PolicyIndexKey {
            src_id,
            dst_id: ANY_ID,
            direction: PolicyDirection::Any.into(),
            _pad: [0; 3],
        },
    ];

    // Kubernetes policy semantics are additive:
    // if any matching selector allows the flow, the flow is allowed.
    // If no index key matches, this remains an implicit allow.
    let mut decision = Action::Allow;
    for idx_key in idx_candidates {
        let Some(ruleset_id) = (unsafe { POLICY_INDEX.get(idx_key) }) else {
            continue;
        };
        // Once any index key matches, default action becomes deny unless a rule allows.
        decision = Action::Deny;
        if ruleset_allows(*ruleset_id, dst_port, proto) {
            return Action::Allow;
        }
    }
    decision
}

#[inline]
pub(crate) fn check_cidr_policy_v4(
    selected_id: IdentityId,
    peer_ip: u32,
    dst_port: u16,
    proto: KubeProtocol,
    direction: PolicyDirection,
) -> Action {
    let Some(ruleset_id) = cidr_ruleset_v4(selected_id, peer_ip, direction) else {
        return Action::Deny;
    };

    if ruleset_allows(ruleset_id, dst_port, proto) {
        Action::Allow
    } else {
        Action::Deny
    }
}

#[inline]
fn cidr_ruleset_v4(
    selected_id: IdentityId,
    peer_ip: u32,
    direction: PolicyDirection,
) -> Option<RulesetId> {
    let direction_u8: u8 = direction.into();
    for direction_candidate in [direction_u8, PolicyDirection::Any.into()] {
        let lookup = LpmKey::new(
            96,
            CidrPolicyMapDataV4 {
                selected_id,
                direction: direction_candidate,
                _pad: [0; 3],
                addr: peer_ip.to_be_bytes(),
            },
        );
        if let Some(ruleset_id) = POLICY_CIDR_V4.get(&lookup) {
            return Some(*ruleset_id);
        }
    }
    None
}

#[inline]
fn ruleset_allows(ruleset_id: RulesetId, dst_port: u16, proto: KubeProtocol) -> bool {
    if ruleset_id == RULESET_NONE {
        return false;
    }

    let rule_candidates = [
        PolicyRuleKey {
            ruleset_id,
            proto: proto as u8,
            _pad0: [0; 3],
            port: dst_port,
            _pad1: [0; 2],
        },
        PolicyRuleKey {
            ruleset_id,
            proto: proto as u8,
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

    for rule_key in rule_candidates {
        if let Some(value) = unsafe { POLICY_RULESET.get(rule_key) }
            && Action::from(value.action) == Action::Allow
        {
            return true;
        }
    }

    false
}
