use std::sync::{Arc, Mutex};

use anyhow::bail;
use aya::maps::{Map, MapData};
use mesh_cni_ebpf_common::policy::{PolicyKey, PolicyValue};
use mesh_cni_policy_controller::PolicyControllerBpf;
use tracing::info;

use crate::{
    Result,
    bpf::{BPF_MAP_POLICY, BpfMap, SharedBpfMap},
};

type PolicyMap = aya::maps::HashMap<MapData, PolicyKey, PolicyValue>;

#[derive(Clone)]
pub struct PolicyState<P>
where
    P: SharedBpfMap<Key = PolicyKey, Value = PolicyValue, KeyOutput = PolicyKey>,
{
    state: P,
}
impl<P> PolicyState<P>
where
    P: SharedBpfMap<Key = PolicyKey, Value = PolicyValue, KeyOutput = PolicyKey>,
{
    pub fn new(policy_map: P) -> Self {
        Self { state: policy_map }
    }
    pub fn update(&self, policy_key: PolicyKey, policy_value: PolicyValue) -> Result<()> {
        self.state.update(policy_key, policy_value)
    }

    // LpmTrie expects big endian order for comparisons
    pub fn delete(&self, policy_key: &PolicyKey) -> Result<()> {
        self.state.delete(policy_key)
    }
    pub fn state(&self) -> Result<ahash::HashMap<PolicyKey, PolicyValue>> {
        self.state.get_state()
    }
}

impl<P> PolicyControllerBpf for PolicyState<P>
where
    P: SharedBpfMap<Key = PolicyKey, Value = PolicyValue, KeyOutput = PolicyKey>,
{
    fn update(&self, key: PolicyKey, value: PolicyValue) -> mesh_cni_policy_controller::Result<()> {
        PolicyState::update(self, key, value)
            .map_err(|e| mesh_cni_policy_controller::Error::BpfError(e.to_string()))
    }

    fn delete(&self, key: &PolicyKey) -> mesh_cni_policy_controller::Result<()> {
        PolicyState::delete(self, key)
            .map_err(|e| mesh_cni_policy_controller::Error::BpfError(e.to_string()))
    }
}

#[derive(Clone)]
pub struct PolicyBpfState {
    state: Arc<Mutex<PolicyBpfStateInner>>,
}

impl PolicyBpfState {
    pub fn try_new() -> Result<Self> {
        let state = PolicyBpfStateInner::try_new()?;
        let state = Arc::new(Mutex::new(state));

        Ok(Self { state })
    }

    pub fn update(&self, key: PolicyKey, value: PolicyValue) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        guard.update(key, value)
    }

    pub fn delete(&self, key: &PolicyKey) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        guard.delete(key)
    }
}

impl SharedBpfMap for PolicyBpfState {
    type Key = PolicyKey;
    type Value = PolicyValue;
    type KeyOutput = PolicyKey;

    fn update(&self, key: Self::Key, value: Self::Value) -> Result<()> {
        PolicyBpfState::update(self, key, value)
    }

    fn delete(&self, key: &Self::Key) -> Result<()> {
        PolicyBpfState::delete(self, key)
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

struct PolicyBpfStateInner {
    cache: ahash::HashMap<PolicyKey, PolicyValue>,
    bpf_map: aya::maps::HashMap<MapData, PolicyKey, PolicyValue>,
}

impl PolicyBpfStateInner {
    pub fn try_new() -> Result<Self> {
        let bpf_map = load_policy_map()?;
        let mut cache = ahash::HashMap::default();
        for kv in bpf_map.iter() {
            match kv {
                Ok((k, v)) => cache.insert(k, v),
                Err(e) => bail!("failed to build policy bpf map cache: {}", e),
            };
        }

        Ok(Self { cache, bpf_map })
    }

    pub fn update(&mut self, key: PolicyKey, value: PolicyValue) -> Result<()> {
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

    pub fn delete(&mut self, key: &PolicyKey) -> Result<()> {
        match self.bpf_map.delete(key) {
            Ok(_) => {
                self.cache.remove(key);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

fn load_policy_map() -> Result<PolicyMap> {
    info!("loading policy map");
    let policy_map = MapData::from_pin(BPF_MAP_POLICY.path())?;
    let policy_map = Map::HashMap(policy_map);
    let policy_map = policy_map.try_into()?;

    Ok(policy_map)
}
