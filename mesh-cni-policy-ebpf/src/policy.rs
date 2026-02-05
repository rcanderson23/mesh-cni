use mesh_cni_ebpf_common::{
    IdentityId,
    policy::{
        ANY_ID, ANY_PORT, Action, PolicyDirection, PolicyIndexKey, PolicyProtocol, PolicyRuleKey,
        RULESET_NONE,
    },
};

use crate::{POLICY_INDEX, POLICY_RULESET};

#[inline]
pub(crate) fn check_policy(
    src_id: IdentityId,
    dst_id: IdentityId,
    dst_port: u16,
    proto: u8,
    direction: PolicyDirection,
) -> Action {
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

    if !found_index {
        return Action::Allow;
    }
    if ruleset_id == RULESET_NONE {
        return Action::Deny;
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

    let mut matched = false;
    for rule_key in rule_candidates {
        if let Some(value) = unsafe { POLICY_RULESET.get(rule_key) } {
            action = value.action;
            matched = true;
            break;
        }
    }
    if matched {
        Action::from(action)
    } else {
        Action::Deny
    }
}
