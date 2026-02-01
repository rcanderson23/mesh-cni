use core::hash::Hasher;
use std::sync::{Arc, Mutex};

use ahash::HashMap;
use k8s_openapi::api::{core::v1::Pod, networking::v1::NetworkPolicy};
use kube::runtime::reflector::Store;
use mesh_cni_crds::v1alpha1::identity::Identity;
use mesh_cni_ebpf_common::policy::{PolicyIndexKey, PolicyRuleKey, PolicyValue};

use crate::PolicyControllerBpf;

pub type RulesetId = u32;
pub type RulesetHash = u64;

pub struct Context<P: PolicyControllerBpf> {
    pub pod_store: Store<Pod>,
    pub policy_store: Store<NetworkPolicy>,
    pub identity_store: Store<Identity>,
    pub policy_bpf_state: P,
    pub ruleset_state: RulesetState,
}

#[derive(Clone, Debug)]
pub struct RulesetEntry {
    ruleset_id: RulesetId,
    refcount: usize,
    rules: Vec<(PolicyRuleKey, PolicyValue)>,
}

pub struct RulesetState {
    inner: Arc<Mutex<RulesetStateInner>>,
}

impl RulesetState {
    pub fn new(
        index_state: &HashMap<PolicyIndexKey, RulesetId>,
        ruleset_state: &HashMap<PolicyRuleKey, PolicyValue>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RulesetStateInner::new(
                index_state,
                ruleset_state,
            ))),
        }
    }

    pub fn acquire_ruleset(
        &self,
        hash: RulesetHash,
        rules: Vec<(PolicyRuleKey, PolicyValue)>,
    ) -> RulesetId {
        let mut guard = self.inner.lock().unwrap();
        guard.acquire_ruleset(hash, rules)
    }

    pub fn release_ruleset(
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
    free_ids: Vec<RulesetId>,
    next_id: RulesetId,
}

impl RulesetStateInner {
    fn new(
        index_state: &HashMap<PolicyIndexKey, RulesetId>,
        ruleset_state: &HashMap<PolicyRuleKey, PolicyValue>,
    ) -> Self {
        let mut by_hash: HashMap<RulesetHash, RulesetEntry> = HashMap::default();
        let mut by_id: HashMap<RulesetId, RulesetHash> = HashMap::default();
        let mut refcounts: HashMap<RulesetId, usize> = HashMap::default();

        for ruleset_id in index_state.values().copied().filter(|id| *id != 0) {
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

            let mut hasher = ahash::AHasher::default();
            for (key, value) in &rules {
                hasher.write_u8(key.proto);
                hasher.write_u16(key.port);
                hasher.write_u8(value.action);
            }
            let hash: RulesetHash = hasher.finish();

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
