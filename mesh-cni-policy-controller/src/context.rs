use core::hash::Hasher;
use std::sync::{Arc, Mutex};

use ahash::HashMap;
use k8s_openapi::api::{
    core::v1::{Namespace, Pod},
    networking::v1::NetworkPolicy,
};
use kube::runtime::reflector::Store;
use mesh_cni_crds::v1alpha1::identity::Identity;
use mesh_cni_ebpf_common::policy::{PolicyIndexKey, PolicyRuleKey, PolicyValue};

use crate::PolicyControllerBpf;

#[allow(unused)]
pub struct Context<P: PolicyControllerBpf> {
    pub pod_store: Store<Pod>,
    pub policy_store: Store<NetworkPolicy>,
    pub namespace_store: Store<Namespace>,
    pub identity_store: Store<Identity>,
    pub policy_bpf_state: P,
    pub ruleset_state: RulesetState,
}

#[derive(Clone, Debug)]
pub struct RulesetEntry {
    ruleset_id: u32,
    refcount: usize,
    rules: Vec<(PolicyRuleKey, PolicyValue)>,
}

impl RulesetEntry {
    pub fn ruleset_id(&self) -> u32 {
        self.ruleset_id
    }

    pub fn refcount(&self) -> usize {
        self.refcount
    }

    pub fn rules(&self) -> &[(PolicyRuleKey, PolicyValue)] {
        &self.rules
    }
}

pub struct RulesetState {
    inner: Arc<Mutex<RulesetStateInner>>,
}

impl RulesetState {
    pub fn new(
        index_state: &HashMap<PolicyIndexKey, u32>,
        ruleset_state: &HashMap<PolicyRuleKey, PolicyValue>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RulesetStateInner::new(
                index_state,
                ruleset_state,
            ))),
        }
    }

    pub fn ruleset_id_for_hash(&self, hash: u64) -> Option<u32> {
        let guard = self.inner.lock().unwrap();
        guard.ruleset_id_for_hash(hash)
    }

    pub fn entry_by_id(&self, ruleset_id: u32) -> Option<RulesetEntry> {
        let guard = self.inner.lock().unwrap();
        guard.entry_by_id(ruleset_id)
    }

    pub fn acquire_ruleset(&self, hash: u64, rules: Vec<(PolicyRuleKey, PolicyValue)>) -> u32 {
        let mut guard = self.inner.lock().unwrap();
        guard.acquire_ruleset(hash, rules)
    }

    pub fn release_ruleset(&self, ruleset_id: u32) -> Option<Vec<(PolicyRuleKey, PolicyValue)>> {
        let mut guard = self.inner.lock().unwrap();
        guard.release_ruleset(ruleset_id)
    }
}

pub struct RulesetStateInner {
    // by_hash enables deduping identical rulesets across many index keys.
    by_hash: HashMap<u64, RulesetEntry>,
    // by_id lets us resolve an existing ruleset_id (from pinned maps) back to its hash.
    by_id: HashMap<u32, u64>,
    free_ids: Vec<u32>,
    next_id: u32,
}

impl RulesetStateInner {
    fn new(
        index_state: &HashMap<PolicyIndexKey, u32>,
        ruleset_state: &HashMap<PolicyRuleKey, PolicyValue>,
    ) -> Self {
        let mut by_hash: HashMap<u64, RulesetEntry> = HashMap::default();
        let mut by_id: HashMap<u32, u64> = HashMap::default();
        let mut refcounts: HashMap<u32, usize> = HashMap::default();

        for ruleset_id in index_state.values().copied().filter(|id| *id != 0) {
            *refcounts.entry(ruleset_id).or_default() += 1;
        }

        let mut rules_by_id: HashMap<u32, Vec<(PolicyRuleKey, PolicyValue)>> = HashMap::default();
        for (key, value) in ruleset_state {
            rules_by_id
                .entry(key.ruleset_id)
                .or_default()
                .push((*key, *value));
        }

        let mut max_id = 0u32;
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
            let hash = hasher.finish();

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

    fn ruleset_id_for_hash(&self, hash: u64) -> Option<u32> {
        self.by_hash.get(&hash).map(|entry| entry.ruleset_id)
    }

    fn entry_by_id(&self, ruleset_id: u32) -> Option<RulesetEntry> {
        let hash = self.by_id.get(&ruleset_id)?;
        self.by_hash.get(hash).cloned()
    }

    fn acquire_ruleset(&mut self, hash: u64, mut rules: Vec<(PolicyRuleKey, PolicyValue)>) -> u32 {
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

    fn release_ruleset(&mut self, ruleset_id: u32) -> Option<Vec<(PolicyRuleKey, PolicyValue)>> {
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
