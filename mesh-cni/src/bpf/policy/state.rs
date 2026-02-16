use std::sync::{Arc, Mutex};

use anyhow::bail;
use aya::maps::{LpmTrie, Map, MapData, lpm_trie::Key as LpmKey};
use mesh_cni_ebpf_common::policy::{
    CidrPolicyMapDataV4, CidrPolicyMapDataV6, CidrPolicyMapKeyV4, CidrPolicyMapKeyV6,
    PolicyIndexKey, PolicyRuleKey, PolicyValue, RulesetId,
};
use mesh_cni_policy_controller::PolicyControllerBpf;
use tracing::info;

use crate::{
    Result,
    bpf::{
        BPF_MAP_POLICY_CIDR_V4, BPF_MAP_POLICY_CIDR_V6, BPF_MAP_POLICY_INDEX,
        BPF_MAP_POLICY_RULESET, BpfMap, SharedBpfMap,
    },
};

type PolicyIndexMap = aya::maps::HashMap<MapData, PolicyIndexKey, RulesetId>;
type PolicyRulesetMap = aya::maps::HashMap<MapData, PolicyRuleKey, PolicyValue>;
type PolicyCidrV4Map = LpmTrie<MapData, CidrPolicyMapDataV4, RulesetId>;
type PolicyCidrV6Map = LpmTrie<MapData, CidrPolicyMapDataV6, RulesetId>;

#[derive(Clone)]
pub struct PolicyState<PI, PR>
where
    PI: SharedBpfMap<Key = PolicyIndexKey, Value = RulesetId, KeyOutput = PolicyIndexKey>,
    PR: SharedBpfMap<Key = PolicyRuleKey, Value = PolicyValue, KeyOutput = PolicyRuleKey>,
{
    index: PI,
    ruleset: PR,
    cidr_v4: PolicyCidrV4BpfState,
    cidr_v6: PolicyCidrV6BpfState,
}
impl<PI, PR> PolicyState<PI, PR>
where
    PI: SharedBpfMap<Key = PolicyIndexKey, Value = RulesetId, KeyOutput = PolicyIndexKey>,
    PR: SharedBpfMap<Key = PolicyRuleKey, Value = PolicyValue, KeyOutput = PolicyRuleKey>,
{
    pub fn new(
        index: PI,
        ruleset: PR,
        cidr_v4: PolicyCidrV4BpfState,
        cidr_v6: PolicyCidrV6BpfState,
    ) -> Self {
        Self {
            index,
            ruleset,
            cidr_v4,
            cidr_v6,
        }
    }

    pub fn update_index(&self, policy_key: PolicyIndexKey, ruleset_id: RulesetId) -> Result<()> {
        self.index.update(policy_key, ruleset_id)
    }

    pub fn delete_index(&self, policy_key: &PolicyIndexKey) -> Result<()> {
        self.index.delete(policy_key)
    }

    pub fn index_state(&self) -> Result<ahash::HashMap<PolicyIndexKey, RulesetId>> {
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

    pub fn update_cidr_v4_index(
        &self,
        key: CidrPolicyMapKeyV4,
        ruleset_id: RulesetId,
    ) -> Result<()> {
        self.cidr_v4.update(key, ruleset_id)
    }

    pub fn delete_cidr_v4_index(&self, key: &CidrPolicyMapKeyV4) -> Result<()> {
        self.cidr_v4.delete(key)
    }

    pub fn cidr_v4_index_state(&self) -> Result<ahash::HashMap<CidrPolicyMapKeyV4, RulesetId>> {
        self.cidr_v4.get_state()
    }

    pub fn update_cidr_v6_index(
        &self,
        key: CidrPolicyMapKeyV6,
        ruleset_id: RulesetId,
    ) -> Result<()> {
        self.cidr_v6.update(key, ruleset_id)
    }

    pub fn delete_cidr_v6_index(&self, key: &CidrPolicyMapKeyV6) -> Result<()> {
        self.cidr_v6.delete(key)
    }

    pub fn cidr_v6_index_state(&self) -> Result<ahash::HashMap<CidrPolicyMapKeyV6, RulesetId>> {
        self.cidr_v6.get_state()
    }
}

impl<PI, PR> PolicyControllerBpf for PolicyState<PI, PR>
where
    PI: SharedBpfMap<Key = PolicyIndexKey, Value = RulesetId, KeyOutput = PolicyIndexKey>,
    PR: SharedBpfMap<Key = PolicyRuleKey, Value = PolicyValue, KeyOutput = PolicyRuleKey>,
{
    fn update_index(
        &self,
        key: PolicyIndexKey,
        ruleset_id: RulesetId,
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

    fn index_state(
        &self,
    ) -> mesh_cni_policy_controller::Result<ahash::HashMap<PolicyIndexKey, RulesetId>> {
        PolicyState::index_state(self)
            .map_err(|e| mesh_cni_policy_controller::Error::BpfError(e.to_string()))
    }

    fn ruleset_state(
        &self,
    ) -> mesh_cni_policy_controller::Result<ahash::HashMap<PolicyRuleKey, PolicyValue>> {
        PolicyState::ruleset_state(self)
            .map_err(|e| mesh_cni_policy_controller::Error::BpfError(e.to_string()))
    }

    fn update_cidr_v4_index(
        &self,
        key: CidrPolicyMapKeyV4,
        ruleset_id: RulesetId,
    ) -> mesh_cni_policy_controller::Result<()> {
        PolicyState::update_cidr_v4_index(self, key, ruleset_id)
            .map_err(|e| mesh_cni_policy_controller::Error::BpfError(e.to_string()))
    }

    fn delete_cidr_v4_index(
        &self,
        key: &CidrPolicyMapKeyV4,
    ) -> mesh_cni_policy_controller::Result<()> {
        PolicyState::delete_cidr_v4_index(self, key)
            .map_err(|e| mesh_cni_policy_controller::Error::BpfError(e.to_string()))
    }

    fn cidr_v4_index_state(
        &self,
    ) -> mesh_cni_policy_controller::Result<ahash::HashMap<CidrPolicyMapKeyV4, RulesetId>> {
        PolicyState::cidr_v4_index_state(self)
            .map_err(|e| mesh_cni_policy_controller::Error::BpfError(e.to_string()))
    }

    fn update_cidr_v6_index(
        &self,
        key: CidrPolicyMapKeyV6,
        ruleset_id: RulesetId,
    ) -> mesh_cni_policy_controller::Result<()> {
        PolicyState::update_cidr_v6_index(self, key, ruleset_id)
            .map_err(|e| mesh_cni_policy_controller::Error::BpfError(e.to_string()))
    }

    fn delete_cidr_v6_index(
        &self,
        key: &CidrPolicyMapKeyV6,
    ) -> mesh_cni_policy_controller::Result<()> {
        PolicyState::delete_cidr_v6_index(self, key)
            .map_err(|e| mesh_cni_policy_controller::Error::BpfError(e.to_string()))
    }

    fn cidr_v6_index_state(
        &self,
    ) -> mesh_cni_policy_controller::Result<ahash::HashMap<CidrPolicyMapKeyV6, RulesetId>> {
        PolicyState::cidr_v6_index_state(self)
            .map_err(|e| mesh_cni_policy_controller::Error::BpfError(e.to_string()))
    }
}

#[derive(Clone)]
pub struct PolicyBpfState {
    index: PolicyIndexBpfState,
    ruleset: PolicyRulesetBpfState,
    cidr_v4: PolicyCidrV4BpfState,
    cidr_v6: PolicyCidrV6BpfState,
}

impl PolicyBpfState {
    pub fn try_new() -> Result<Self> {
        let index = PolicyIndexBpfState::try_new()?;
        let ruleset = PolicyRulesetBpfState::try_new()?;
        let cidr_v4 = PolicyCidrV4BpfState::try_new()?;
        let cidr_v6 = PolicyCidrV6BpfState::try_new()?;

        Ok(Self {
            index,
            ruleset,
            cidr_v4,
            cidr_v6,
        })
    }

    pub fn index(&self) -> PolicyIndexBpfState {
        self.index.clone()
    }

    pub fn ruleset(&self) -> PolicyRulesetBpfState {
        self.ruleset.clone()
    }

    pub fn cidr_v4(&self) -> PolicyCidrV4BpfState {
        self.cidr_v4.clone()
    }

    pub fn cidr_v6(&self) -> PolicyCidrV6BpfState {
        self.cidr_v6.clone()
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

    pub fn update(&self, key: PolicyIndexKey, value: RulesetId) -> Result<()> {
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
    type Value = RulesetId;
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
    cache: ahash::HashMap<PolicyIndexKey, RulesetId>,
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

    pub fn update(&mut self, key: PolicyIndexKey, value: RulesetId) -> Result<()> {
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

#[derive(Clone)]
pub struct PolicyCidrV4BpfState {
    state: Arc<Mutex<PolicyCidrV4BpfStateInner>>,
}

impl PolicyCidrV4BpfState {
    pub fn try_new() -> Result<Self> {
        let state = PolicyCidrV4BpfStateInner::try_new()?;
        let state = Arc::new(Mutex::new(state));
        Ok(Self { state })
    }

    pub fn update(&self, key: CidrPolicyMapKeyV4, value: RulesetId) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        guard.update(key, value)
    }

    pub fn delete(&self, key: &CidrPolicyMapKeyV4) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        guard.delete(key)
    }

    pub fn get_state(&self) -> Result<ahash::HashMap<CidrPolicyMapKeyV4, RulesetId>> {
        let guard = self.state.lock().unwrap();
        Ok(guard.cache.clone())
    }
}

struct PolicyCidrV4BpfStateInner {
    cache: ahash::HashMap<CidrPolicyMapKeyV4, RulesetId>,
    bpf_map: PolicyCidrV4Map,
}

impl PolicyCidrV4BpfStateInner {
    fn try_new() -> Result<Self> {
        let bpf_map = load_policy_cidr_v4_map()?;
        let mut cache = ahash::HashMap::default();
        for kv in bpf_map.iter() {
            match kv {
                Ok((key, value)) => cache.insert(cidr_v4_from_lpm_key(key), value),
                Err(e) => bail!("failed to build policy cidr v4 map cache: {}", e),
            };
        }
        Ok(Self { cache, bpf_map })
    }

    fn update(&mut self, key: CidrPolicyMapKeyV4, value: RulesetId) -> Result<()> {
        if let Some(current) = self.cache.get(&key)
            && *current == value
        {
            return Ok(());
        }
        let lpm_key = cidr_v4_to_lpm_key(key);
        match self.bpf_map.insert(&lpm_key, value, 0) {
            Ok(_) => {
                self.cache.insert(key, value);
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    fn delete(&mut self, key: &CidrPolicyMapKeyV4) -> Result<()> {
        let lpm_key = cidr_v4_to_lpm_key(*key);
        match self.bpf_map.remove(&lpm_key) {
            Ok(_) => {
                self.cache.remove(key);
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[derive(Clone)]
pub struct PolicyCidrV6BpfState {
    state: Arc<Mutex<PolicyCidrV6BpfStateInner>>,
}

impl PolicyCidrV6BpfState {
    pub fn try_new() -> Result<Self> {
        let state = PolicyCidrV6BpfStateInner::try_new()?;
        let state = Arc::new(Mutex::new(state));
        Ok(Self { state })
    }

    pub fn update(&self, key: CidrPolicyMapKeyV6, value: RulesetId) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        guard.update(key, value)
    }

    pub fn delete(&self, key: &CidrPolicyMapKeyV6) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        guard.delete(key)
    }

    pub fn get_state(&self) -> Result<ahash::HashMap<CidrPolicyMapKeyV6, RulesetId>> {
        let guard = self.state.lock().unwrap();
        Ok(guard.cache.clone())
    }
}

struct PolicyCidrV6BpfStateInner {
    cache: ahash::HashMap<CidrPolicyMapKeyV6, RulesetId>,
    bpf_map: PolicyCidrV6Map,
}

impl PolicyCidrV6BpfStateInner {
    fn try_new() -> Result<Self> {
        let bpf_map = load_policy_cidr_v6_map()?;
        let mut cache = ahash::HashMap::default();
        for kv in bpf_map.iter() {
            match kv {
                Ok((key, value)) => cache.insert(cidr_v6_from_lpm_key(key), value),
                Err(e) => bail!("failed to build policy cidr v6 map cache: {}", e),
            };
        }
        Ok(Self { cache, bpf_map })
    }

    fn update(&mut self, key: CidrPolicyMapKeyV6, value: RulesetId) -> Result<()> {
        if let Some(current) = self.cache.get(&key)
            && *current == value
        {
            return Ok(());
        }
        let lpm_key = cidr_v6_to_lpm_key(key);
        match self.bpf_map.insert(&lpm_key, value, 0) {
            Ok(_) => {
                self.cache.insert(key, value);
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    fn delete(&mut self, key: &CidrPolicyMapKeyV6) -> Result<()> {
        let lpm_key = cidr_v6_to_lpm_key(*key);
        match self.bpf_map.remove(&lpm_key) {
            Ok(_) => {
                self.cache.remove(key);
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}

fn cidr_v4_to_lpm_key(key: CidrPolicyMapKeyV4) -> LpmKey<CidrPolicyMapDataV4> {
    LpmKey::new(
        key.prefix_len,
        CidrPolicyMapDataV4 {
            selected_id: key.selected_id,
            direction: key.direction,
            _pad: key._pad,
            addr: key.addr,
        },
    )
}

fn cidr_v4_from_lpm_key(key: LpmKey<CidrPolicyMapDataV4>) -> CidrPolicyMapKeyV4 {
    let data = key.data();
    CidrPolicyMapKeyV4 {
        prefix_len: key.prefix_len(),
        selected_id: data.selected_id,
        direction: data.direction,
        _pad: data._pad,
        addr: data.addr,
    }
}

fn cidr_v6_to_lpm_key(key: CidrPolicyMapKeyV6) -> LpmKey<CidrPolicyMapDataV6> {
    LpmKey::new(
        key.prefix_len,
        CidrPolicyMapDataV6 {
            selected_id: key.selected_id,
            direction: key.direction,
            _pad: key._pad,
            addr: key.addr,
        },
    )
}

fn cidr_v6_from_lpm_key(key: LpmKey<CidrPolicyMapDataV6>) -> CidrPolicyMapKeyV6 {
    let data = key.data();
    CidrPolicyMapKeyV6 {
        prefix_len: key.prefix_len(),
        selected_id: data.selected_id,
        direction: data.direction,
        _pad: data._pad,
        addr: data.addr,
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

fn load_policy_cidr_v4_map() -> Result<PolicyCidrV4Map> {
    info!("loading policy cidr v4 map");
    let policy_map = MapData::from_pin(BPF_MAP_POLICY_CIDR_V4.path())?;
    let policy_map = Map::LpmTrie(policy_map);
    let policy_map = policy_map.try_into()?;

    Ok(policy_map)
}

fn load_policy_cidr_v6_map() -> Result<PolicyCidrV6Map> {
    info!("loading policy cidr v6 map");
    let policy_map = MapData::from_pin(BPF_MAP_POLICY_CIDR_V6.path())?;
    let policy_map = Map::LpmTrie(policy_map);
    let policy_map = policy_map.try_into()?;

    Ok(policy_map)
}
