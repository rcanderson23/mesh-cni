use aya_ebpf::{maps::lpm_trie::Key as LpmKey, programs::TcContext};
use aya_log_ebpf::error;
use mesh_cni_ebpf_common::{
    IdentityId,
    conntrack::{ConntrackKeyV4, ConntrackValue},
    policy::{
        ANY_ID, ANY_PORT, Action, CidrPolicyMapDataV4, PolicyDirection, PolicyIndexKey,
        PolicyProtocol, PolicyRuleKey, RULESET_NONE, RulesetId,
    },
};

use crate::{CONNTRACK_V4, POLICY_CIDR_V4, POLICY_INDEX, POLICY_RULESET};

#[inline]
pub(crate) fn conntrack_hit(
    ctx: &TcContext,
    ct_key: ConntrackKeyV4,
    ct_rev: ConntrackKeyV4,
    now: u64,
) -> bool {
    if unsafe { CONNTRACK_V4.get(ct_key) }.is_some() {
        if CONNTRACK_V4
            .insert(ct_key, ConntrackValue { last_seen_ns: now }, 0)
            .is_err()
        {
            error!(ctx, "failed to insert into conntrack");
        };
        return true;
    }
    if unsafe { CONNTRACK_V4.get(ct_rev) }.is_some() {
        if CONNTRACK_V4
            .insert(ct_rev, ConntrackValue { last_seen_ns: now }, 0)
            .is_err()
        {
            error!(ctx, "failed to insert into conntrack");
        };
        return true;
    }
    false
}

#[inline]
/// Generates the conntrack keys to be checked.
/// IPs and ports are expected to be in host order
pub(crate) fn conntrack_keys(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    initiator_id: IdentityId,
) -> (ConntrackKeyV4, ConntrackKeyV4) {
    (
        ConntrackKeyV4 {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
            _pad: [0; 3],
            initiator_id,
        },
        ConntrackKeyV4 {
            src_ip: dst_ip,
            dst_ip: src_ip,
            src_port: dst_port,
            dst_port: src_port,
            proto,
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
    proto: u8,
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
    proto: u8,
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
                addr: peer_ip.to_be(),
            },
        );
        if let Some(ruleset_id) = POLICY_CIDR_V4.get(&lookup) {
            return Some(*ruleset_id);
        }
    }
    None
}

#[inline]
fn ruleset_allows(ruleset_id: RulesetId, dst_port: u16, proto: u8) -> bool {
    if ruleset_id == RULESET_NONE {
        return false;
    }

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

    for rule_key in rule_candidates {
        if let Some(value) = unsafe { POLICY_RULESET.get(rule_key) }
            && Action::from(value.action) == Action::Allow
        {
            return true;
        }
    }

    false
}
