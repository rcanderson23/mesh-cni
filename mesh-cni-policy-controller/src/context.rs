use core::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use ahash::HashMap;
use k8s_openapi::api::{core::v1::Pod, networking::v1::NetworkPolicy};
use kube::runtime::reflector::Store;
use mesh_cni_crds::v1alpha1::{
    cidridentity::CIDRIdentity, identity::Identity, meshidentityslice::MeshIdentitySlice,
};
use mesh_cni_ebpf_common::policy::{
    CidrPolicyMapKey, PolicyIndexKey, PolicyRuleKey, PolicyValue, RulesetId,
};

use crate::PolicyControllerBpf;

pub type RulesetHash = u64;

pub fn hash_rule_triples<I>(triples: I) -> RulesetHash
where
    // (Proto, Port, Action)
    I: IntoIterator<Item = (u8, u16, u8)>,
{
    let mut hasher = ahash::AHasher::default();
    for triple in triples {
        triple.hash(&mut hasher);
    }
    hasher.finish()
}

pub struct Context<P: PolicyControllerBpf> {
    pub pod_store: Store<Pod>,
    pub policy_store: Store<NetworkPolicy>,
    pub identity_store: Store<Identity>,
    pub cidr_identity_store: Store<CIDRIdentity>,
    pub mesh_identity_slice_store: Store<MeshIdentitySlice>,
    pub policy_bpf_state: P,
    pub ruleset_state: RulesetState,
}

#[derive(Clone, Debug)]
pub(crate) struct RulesetEntry {
    ruleset_id: RulesetId,
    refcount: usize,
    rules: Vec<(PolicyRuleKey, PolicyValue)>,
}

pub struct RulesetState {
    inner: Arc<Mutex<RulesetStateInner>>,
}

impl RulesetState {
    #[cfg(test)]
    pub(crate) fn new(
        index_state: &HashMap<PolicyIndexKey, RulesetId>,
        ruleset_state: &HashMap<PolicyRuleKey, PolicyValue>,
    ) -> Self {
        let cidr_state = HashMap::default();
        Self::new_with_cidr(index_state, &cidr_state, ruleset_state)
    }

    pub(crate) fn new_with_cidr(
        index_state: &HashMap<PolicyIndexKey, RulesetId>,
        cidr_state: &HashMap<CidrPolicyMapKey, RulesetId>,
        ruleset_state: &HashMap<PolicyRuleKey, PolicyValue>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RulesetStateInner::new(
                index_state,
                cidr_state,
                ruleset_state,
            ))),
        }
    }

    pub(crate) fn acquire_ruleset(
        &self,
        hash: RulesetHash,
        rules: Vec<(PolicyRuleKey, PolicyValue)>,
    ) -> RulesetId {
        let mut guard = self.inner.lock().unwrap();
        guard.acquire_ruleset(hash, rules)
    }

    pub(crate) fn release_ruleset(
        &self,
        ruleset_id: RulesetId,
    ) -> Option<Vec<(PolicyRuleKey, PolicyValue)>> {
        let mut guard = self.inner.lock().unwrap();
        guard.release_ruleset(ruleset_id)
    }
}

pub struct RulesetStateInner {
    // by_hash enables deduping identical rulesets across many index keys.
    by_hash: HashMap<RulesetHash, RulesetEntry>,
    // by_id lets us resolve an existing ruleset_id (from pinned maps) back to its hash.
    by_id: HashMap<RulesetId, RulesetHash>,
    // free_ids is the ids that have recently been freed so that they can be re-used
    free_ids: Vec<RulesetId>,
    // next_id tracks the next RulesetId to use
    next_id: RulesetId,
}

impl RulesetStateInner {
    fn new(
        index_state: &HashMap<PolicyIndexKey, RulesetId>,
        cidr_state: &HashMap<CidrPolicyMapKey, RulesetId>,
        ruleset_state: &HashMap<PolicyRuleKey, PolicyValue>,
    ) -> Self {
        let mut by_hash: HashMap<RulesetHash, RulesetEntry> = HashMap::default();
        let mut by_id: HashMap<RulesetId, RulesetHash> = HashMap::default();
        let mut refcounts: HashMap<RulesetId, usize> = HashMap::default();

        for ruleset_id in index_state.values().copied().filter(|id| *id != 0) {
            *refcounts.entry(ruleset_id).or_default() += 1;
        }
        for ruleset_id in cidr_state.values().copied().filter(|id| *id != 0) {
            *refcounts.entry(ruleset_id).or_default() += 1;
        }

        let mut rules_by_id: HashMap<RulesetId, Vec<(PolicyRuleKey, PolicyValue)>> =
            HashMap::default();
        for (key, value) in ruleset_state {
            rules_by_id
                .entry(key.ruleset_id)
                .or_default()
                .push((*key, *value));
        }

        let mut max_id: RulesetId = 0;
        for (ruleset_id, mut rules) in rules_by_id {
            if ruleset_id > max_id {
                max_id = ruleset_id;
            }
            rules.sort_by_key(|(key, value)| (key.proto, key.port, value.action));

            let hash = hash_rule_triples(
                rules
                    .iter()
                    .map(|(key, value)| (key.proto, key.port, value.action)),
            );

            by_id.insert(ruleset_id, hash);
            by_hash.entry(hash).or_insert(RulesetEntry {
                ruleset_id,
                refcount: *refcounts.get(&ruleset_id).unwrap_or(&0),
                rules,
            });
        }

        for ruleset_id in index_state.values().copied().filter(|id| *id != 0) {
            if ruleset_id > max_id {
                max_id = ruleset_id;
            }
        }
        for ruleset_id in cidr_state.values().copied().filter(|id| *id != 0) {
            if ruleset_id > max_id {
                max_id = ruleset_id;
            }
        }

        Self {
            by_hash,
            by_id,
            free_ids: Vec::new(),
            next_id: max_id.saturating_add(1),
        }
    }

    fn acquire_ruleset(
        &mut self,
        hash: RulesetHash,
        mut rules: Vec<(PolicyRuleKey, PolicyValue)>,
    ) -> RulesetId {
        if let Some(entry) = self.by_hash.get_mut(&hash) {
            entry.refcount += 1;
            return entry.ruleset_id;
        }

        let ruleset_id = self.free_ids.pop().unwrap_or_else(|| {
            let next = self.next_id;
            self.next_id = self.next_id.saturating_add(1);
            next
        });

        for (key, _) in &mut rules {
            key.ruleset_id = ruleset_id;
        }

        self.by_id.insert(ruleset_id, hash);
        self.by_hash.insert(
            hash,
            RulesetEntry {
                ruleset_id,
                refcount: 1,
                rules,
            },
        );

        ruleset_id
    }

    fn release_ruleset(
        &mut self,
        ruleset_id: RulesetId,
    ) -> Option<Vec<(PolicyRuleKey, PolicyValue)>> {
        let hash = self.by_id.get(&ruleset_id).copied()?;
        let entry = self.by_hash.get_mut(&hash)?;
        if entry.refcount > 1 {
            entry.refcount -= 1;
            return None;
        }

        let removed = self.by_hash.remove(&hash)?;
        self.by_id.remove(&ruleset_id);
        self.free_ids.push(ruleset_id);
        Some(removed.rules)
    }
}
