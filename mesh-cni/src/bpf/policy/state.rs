use std::sync::{Arc, Mutex};

use anyhow::bail;
use aya::maps::{Map, MapData};
use mesh_cni_ebpf_common::policy::{PolicyIndexKey, PolicyRuleKey, PolicyValue};
use mesh_cni_policy_controller::PolicyControllerBpf;
use tracing::info;

use crate::{
    Result,
    bpf::{BPF_MAP_POLICY_INDEX, BPF_MAP_POLICY_RULESET, BpfMap, SharedBpfMap},
};

type PolicyIndexMap = aya::maps::HashMap<MapData, PolicyIndexKey, u32>;
type PolicyRulesetMap = aya::maps::HashMap<MapData, PolicyRuleKey, PolicyValue>;

#[derive(Clone)]
pub struct PolicyState<PI, PR>
where
    PI: SharedBpfMap<Key = PolicyIndexKey, Value = u32, KeyOutput = PolicyIndexKey>,
    PR: SharedBpfMap<Key = PolicyRuleKey, Value = PolicyValue, KeyOutput = PolicyRuleKey>,
{
    index: PI,
    ruleset: PR,
}
impl<PI, PR> PolicyState<PI, PR>
where
    PI: SharedBpfMap<Key = PolicyIndexKey, Value = u32, KeyOutput = PolicyIndexKey>,
    PR: SharedBpfMap<Key = PolicyRuleKey, Value = PolicyValue, KeyOutput = PolicyRuleKey>,
{
    pub fn new(index: PI, ruleset: PR) -> Self {
        Self { index, ruleset }
    }

    pub fn update_index(&self, policy_key: PolicyIndexKey, ruleset_id: u32) -> Result<()> {
        self.index.update(policy_key, ruleset_id)
    }

    pub fn delete_index(&self, policy_key: &PolicyIndexKey) -> Result<()> {
        self.index.delete(policy_key)
    }

    pub fn index_state(&self) -> Result<ahash::HashMap<PolicyIndexKey, u32>> {
        self.index.get_state()
    }

    pub fn update_rule(&self, rule_key: PolicyRuleKey, policy_value: PolicyValue) -> Result<()> {
        self.ruleset.update(rule_key, policy_value)
    }

    pub fn delete_rule(&self, rule_key: &PolicyRuleKey) -> Result<()> {
        self.ruleset.delete(rule_key)
    }

    pub fn ruleset_state(&self) -> Result<ahash::HashMap<PolicyRuleKey, PolicyValue>> {
        self.ruleset.get_state()
    }
}

impl<PI, PR> PolicyControllerBpf for PolicyState<PI, PR>
where
    PI: SharedBpfMap<Key = PolicyIndexKey, Value = u32, KeyOutput = PolicyIndexKey>,
    PR: SharedBpfMap<Key = PolicyRuleKey, Value = PolicyValue, KeyOutput = PolicyRuleKey>,
{
    fn update_index(
        &self,
        key: PolicyIndexKey,
        ruleset_id: u32,
    ) -> mesh_cni_policy_controller::Result<()> {
        PolicyState::update_index(self, key, ruleset_id)
            .map_err(|e| mesh_cni_policy_controller::Error::BpfError(e.to_string()))
    }

    fn delete_index(&self, key: &PolicyIndexKey) -> mesh_cni_policy_controller::Result<()> {
        PolicyState::delete_index(self, key)
            .map_err(|e| mesh_cni_policy_controller::Error::BpfError(e.to_string()))
    }

    fn update_rule(
        &self,
        key: PolicyRuleKey,
        value: PolicyValue,
    ) -> mesh_cni_policy_controller::Result<()> {
        PolicyState::update_rule(self, key, value)
            .map_err(|e| mesh_cni_policy_controller::Error::BpfError(e.to_string()))
    }

    fn delete_rule(&self, key: &PolicyRuleKey) -> mesh_cni_policy_controller::Result<()> {
        PolicyState::delete_rule(self, key)
            .map_err(|e| mesh_cni_policy_controller::Error::BpfError(e.to_string()))
    }
}

#[derive(Clone)]
pub struct PolicyBpfState {
    index: PolicyIndexBpfState,
    ruleset: PolicyRulesetBpfState,
}

impl PolicyBpfState {
    pub fn try_new() -> Result<Self> {
        let index = PolicyIndexBpfState::try_new()?;
        let ruleset = PolicyRulesetBpfState::try_new()?;

        Ok(Self { index, ruleset })
    }

    pub fn index(&self) -> PolicyIndexBpfState {
        self.index.clone()
    }

    pub fn ruleset(&self) -> PolicyRulesetBpfState {
        self.ruleset.clone()
    }
}

#[derive(Clone)]
pub struct PolicyIndexBpfState {
    state: Arc<Mutex<PolicyIndexBpfStateInner>>,
}

impl PolicyIndexBpfState {
    pub fn try_new() -> Result<Self> {
        let state = PolicyIndexBpfStateInner::try_new()?;
        let state = Arc::new(Mutex::new(state));

        Ok(Self { state })
    }

    pub fn update(&self, key: PolicyIndexKey, value: u32) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        guard.update(key, value)
    }

    pub fn delete(&self, key: &PolicyIndexKey) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        guard.delete(key)
    }
}

impl SharedBpfMap for PolicyIndexBpfState {
    type Key = PolicyIndexKey;
    type Value = u32;
    type KeyOutput = PolicyIndexKey;

    fn update(&self, key: Self::Key, value: Self::Value) -> Result<()> {
        PolicyIndexBpfState::update(self, key, value)
    }

    fn delete(&self, key: &Self::Key) -> Result<()> {
        PolicyIndexBpfState::delete(self, key)
    }

    fn get(&self, key: &Self::Key) -> Result<Self::Value> {
        let guard = self.state.lock().unwrap();
        guard
            .cache
            .get(key)
            .ok_or(anyhow::anyhow!("key does not exist"))
            .copied()
    }

    fn get_state(&self) -> Result<ahash::HashMap<Self::KeyOutput, Self::Value>> {
        let guard = self.state.lock().unwrap();
        Ok(guard.cache.clone())
    }
}

struct PolicyIndexBpfStateInner {
    cache: ahash::HashMap<PolicyIndexKey, u32>,
    bpf_map: PolicyIndexMap,
}

impl PolicyIndexBpfStateInner {
    pub fn try_new() -> Result<Self> {
        let bpf_map = load_policy_index_map()?;
        let mut cache = ahash::HashMap::default();
        for kv in bpf_map.iter() {
            match kv {
                Ok((k, v)) => cache.insert(k, v),
                Err(e) => bail!("failed to build policy bpf map cache: {}", e),
            };
        }

        Ok(Self { cache, bpf_map })
    }

    pub fn update(&mut self, key: PolicyIndexKey, value: u32) -> Result<()> {
        if let Some(current) = self.cache.get(&key)
            && *current == value
        {
            return Ok(());
        };
        match self.bpf_map.update(key, value) {
            Ok(_) => {
                self.cache.insert(key, value);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn delete(&mut self, key: &PolicyIndexKey) -> Result<()> {
        match self.bpf_map.delete(key) {
            Ok(_) => {
                self.cache.remove(key);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

#[derive(Clone)]
pub struct PolicyRulesetBpfState {
    state: Arc<Mutex<PolicyRulesetBpfStateInner>>,
}

impl PolicyRulesetBpfState {
    pub fn try_new() -> Result<Self> {
        let state = PolicyRulesetBpfStateInner::try_new()?;
        let state = Arc::new(Mutex::new(state));

        Ok(Self { state })
    }

    pub fn update(&self, key: PolicyRuleKey, value: PolicyValue) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        guard.update(key, value)
    }

    pub fn delete(&self, key: &PolicyRuleKey) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        guard.delete(key)
    }
}

impl SharedBpfMap for PolicyRulesetBpfState {
    type Key = PolicyRuleKey;
    type Value = PolicyValue;
    type KeyOutput = PolicyRuleKey;

    fn update(&self, key: Self::Key, value: Self::Value) -> Result<()> {
        PolicyRulesetBpfState::update(self, key, value)
    }

    fn delete(&self, key: &Self::Key) -> Result<()> {
        PolicyRulesetBpfState::delete(self, key)
    }

    fn get(&self, key: &Self::Key) -> Result<Self::Value> {
        let guard = self.state.lock().unwrap();
        guard
            .cache
            .get(key)
            .ok_or(anyhow::anyhow!("key does not exist"))
            .copied()
    }

    fn get_state(&self) -> Result<ahash::HashMap<Self::KeyOutput, Self::Value>> {
        let guard = self.state.lock().unwrap();
        Ok(guard.cache.clone())
    }
}

struct PolicyRulesetBpfStateInner {
    cache: ahash::HashMap<PolicyRuleKey, PolicyValue>,
    bpf_map: PolicyRulesetMap,
}

impl PolicyRulesetBpfStateInner {
    pub fn try_new() -> Result<Self> {
        let bpf_map = load_policy_ruleset_map()?;
        let mut cache = ahash::HashMap::default();
        for kv in bpf_map.iter() {
            match kv {
                Ok((k, v)) => cache.insert(k, v),
                Err(e) => bail!("failed to build policy bpf map cache: {}", e),
            };
        }

        Ok(Self { cache, bpf_map })
    }

    pub fn update(&mut self, key: PolicyRuleKey, value: PolicyValue) -> Result<()> {
        if let Some(current) = self.cache.get(&key)
            && *current == value
        {
            return Ok(());
        };
        match self.bpf_map.update(key, value) {
            Ok(_) => {
                self.cache.insert(key, value);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn delete(&mut self, key: &PolicyRuleKey) -> Result<()> {
        match self.bpf_map.delete(key) {
            Ok(_) => {
                self.cache.remove(key);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

fn load_policy_index_map() -> Result<PolicyIndexMap> {
    info!("loading policy index map");
    let policy_map = MapData::from_pin(BPF_MAP_POLICY_INDEX.path())?;
    let policy_map = Map::HashMap(policy_map);
    let policy_map = policy_map.try_into()?;

    Ok(policy_map)
}

fn load_policy_ruleset_map() -> Result<PolicyRulesetMap> {
    info!("loading policy ruleset map");
    let policy_map = MapData::from_pin(BPF_MAP_POLICY_RULESET.path())?;
    let policy_map = Map::HashMap(policy_map);
    let policy_map = policy_map.try_into()?;

    Ok(policy_map)
}
