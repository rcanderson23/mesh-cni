pub mod cni;
pub mod ip;
pub mod loader;
pub mod service;

use std::{borrow::BorrowMut, hash::Hash};

use anyhow::anyhow;
use aya::{
    Pod,
    maps::{HashMap, LpmTrie, MapData, lpm_trie::Key as LpmKey},
};
use ipnetwork::IpNetwork;
use mesh_cni_ebpf_common::IdentityId;

use crate::{Result, bpf::ip::LpmKeyNetwork};

pub(crate) const BPF_PROGRAM_INGRESS_TC: BpfNamePath = BpfNamePath::Program("mesh_cni_ingress");
pub const BPF_PROGRAM_CGROUP_CONNECT_V4: BpfNamePath =
    BpfNamePath::Program("mesh_cni_cgroup_connect4");
pub const BPF_LINK_CGROUP_CONNECT_V4_PATH: &str = "/sys/fs/bpf/mesh/links/mesh_cni_cgroup_connect4";

pub type IdentityMapV4 = LpmTrie<MapData, u32, IdentityId>;
pub type IdentityMapV6 = LpmTrie<MapData, u128, IdentityId>;

pub const BPF_MAP_IDENTITY_V4: BpfNamePath = BpfNamePath::Map("identity_v4");
pub const BPF_MAP_IDENTITY_V6: BpfNamePath = BpfNamePath::Map("identity_v6");
pub const BPF_MAP_SERVICES_V4: BpfNamePath = BpfNamePath::Map("services_v4");
pub const BPF_MAP_SERVICES_V6: BpfNamePath = BpfNamePath::Map("services_v6");
pub const BPF_MAP_ENDPOINTS_V4: BpfNamePath = BpfNamePath::Map("endpoints_v4");
pub const BPF_MAP_ENDPOINTS_V6: BpfNamePath = BpfNamePath::Map("endpoints_v6");

pub const BPF_MESH_FS_DIR: &str = "/sys/fs/bpf/mesh";
pub const BPF_MESH_MAPS_DIR: &str = "/sys/fs/bpf/mesh/maps";
pub const BPF_MESH_PROG_DIR: &str = "/sys/fs/bpf/mesh/programs";
pub const BPF_MESH_LINKS_DIR: &str = "/sys/fs/bpf/mesh/links";

pub(crate) const POLICY_MAPS_LIST: [BpfNamePath; 2] = [BPF_MAP_IDENTITY_V4, BPF_MAP_IDENTITY_V6];

pub(crate) const SERVICE_MAPS_LIST: [BpfNamePath; 4] = [
    BPF_MAP_SERVICES_V4,
    BPF_MAP_SERVICES_V6,
    BPF_MAP_ENDPOINTS_V4,
    BPF_MAP_ENDPOINTS_V6,
];

pub(crate) const PROG_LIST: [BpfNamePath; 2] =
    [BPF_PROGRAM_CGROUP_CONNECT_V4, BPF_PROGRAM_INGRESS_TC];

pub enum BpfNamePath {
    Map(&'static str),
    Program(&'static str),
}

impl BpfNamePath {
    pub fn name(&self) -> &'static str {
        match &self {
            BpfNamePath::Map(n) => n,
            BpfNamePath::Program(n) => n,
        }
    }

    pub fn path(&self) -> String {
        match &self {
            BpfNamePath::Map(n) => format!("{BPF_MESH_MAPS_DIR}/{n}"),
            BpfNamePath::Program(n) => format!("{BPF_MESH_PROG_DIR}/{n}"),
        }
    }
}

pub trait BpfMap {
    type Key;
    type Value;
    type KeyOutput;
    fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<()>;
    fn delete(&mut self, key: &Self::Key) -> Result<()>;
    fn get(&self, key: &Self::Key) -> Result<Self::Value>;
    fn get_state(&self) -> Result<ahash::HashMap<Self::KeyOutput, Self::Value>>;
}

impl<T, K, V> BpfMap for HashMap<T, K, V>
where
    T: BorrowMut<MapData>,
    K: Pod + Eq + Hash,
    V: Pod,
{
    type Key = K;
    type Value = V;
    type KeyOutput = K;
    fn update(&mut self, key: K, value: V) -> Result<()> {
        Ok(self.insert(key, value, 0)?)
    }
    fn delete(&mut self, key: &K) -> Result<()> {
        Ok(self.remove(key)?)
    }
    fn get(&self, key: &K) -> Result<V> {
        Ok(<HashMap<T, K, V>>::get(self, key, 0)?)
    }
    fn get_state(&self) -> Result<ahash::HashMap<K, V>> {
        let mut map = ahash::HashMap::default();
        for v in self.iter() {
            match v {
                Ok((k, v)) => {
                    map.insert(k, v);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(map)
    }
}

impl<K, V> BpfMap for ahash::HashMap<K, V>
where
    K: Pod + Eq + Hash,
    V: Pod,
{
    type Key = K;
    type Value = V;
    type KeyOutput = K;
    fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<()> {
        self.insert(key, value);
        Ok(())
    }
    fn delete(&mut self, key: &K) -> Result<()> {
        self.remove(key);
        Ok(())
    }
    fn get(&self, key: &K) -> Result<V> {
        match <ahash::HashMap<K, V>>::get(self, key) {
            Some(i) => Ok(*i),
            None => Err(anyhow!("not found")),
        }
    }
    fn get_state(&self) -> Result<ahash::HashMap<K, V>> {
        Ok(self.clone())
    }
}

impl<T, V> BpfMap for LpmTrie<T, u32, V>
where
    T: BorrowMut<MapData>,
    // K: Pod + Eq + Hash + From<LpmKey<>>,
    V: Pod,
{
    type Key = LpmKey<u32>;
    type Value = V;
    type KeyOutput = IpNetwork;
    fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<()> {
        Ok(self.insert(&key, value, 0)?)
    }
    fn delete(&mut self, key: &Self::Key) -> Result<()> {
        Ok(self.remove(key)?)
    }
    fn get(&self, key: &Self::Key) -> Result<Self::Value> {
        Ok(<LpmTrie<T, u32, V>>::get(self, key, 0)?)
    }
    fn get_state(&self) -> Result<ahash::HashMap<Self::KeyOutput, Self::Value>> {
        let mut map = ahash::HashMap::default();
        for v in self.iter() {
            match v {
                Ok((k, v)) => {
                    let k = <u32 as LpmKeyNetwork>::key_to_network(k);
                    map.insert(k, v);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(map)
    }
}
impl<T, V> BpfMap for LpmTrie<T, u128, V>
where
    T: BorrowMut<MapData>,
    // K: Pod + Eq + Hash + From<LpmKey<>>,
    V: Pod,
{
    type Key = LpmKey<u128>;
    type Value = V;
    type KeyOutput = IpNetwork;
    fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<()> {
        Ok(self.insert(&key, value, 0)?)
    }
    fn delete(&mut self, key: &Self::Key) -> Result<()> {
        Ok(self.remove(key)?)
    }
    fn get(&self, key: &Self::Key) -> Result<Self::Value> {
        Ok(<LpmTrie<T, u128, V>>::get(self, key, 0)?)
    }
    fn get_state(&self) -> Result<ahash::HashMap<Self::KeyOutput, Self::Value>> {
        let mut map = ahash::HashMap::default();
        for v in self.iter() {
            match v {
                Ok((k, v)) => {
                    let k = <u128 as LpmKeyNetwork>::key_to_network(k);
                    map.insert(k, v);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(map)
    }
}
