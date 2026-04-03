pub mod conntrack;
pub mod ip;
pub mod loader;
pub mod policy;
pub mod routes;
pub mod service;

use std::{borrow::BorrowMut, hash::Hash};

use anyhow::anyhow;
use aya::{
    Pod,
    maps::{HashMap, LpmTrie, MapData, MapError, lpm_trie::Key as LpmKey},
};
use ipnetwork::IpNetwork;
use mesh_cni_ebpf_common::IdentityId;
pub use mesh_cni_ebpf_meta::{
    BPF_LINK_CGROUP_CONNECT_V4_PATH, BPF_MAP_CONNTRACK_V4, BPF_MAP_ENDPOINTS_V4,
    BPF_MAP_ENDPOINTS_V6, BPF_MAP_IDENTITY_V4, BPF_MAP_IDENTITY_V6, BPF_MAP_NODEPORT_CONNTRACK_V4,
    BPF_MAP_NODEPORT_LOCAL_ADDRS_V4, BPF_MAP_NODEPORT_REV_NAT_V4, BPF_MAP_NODEPORT_SERVICES_V4,
    BPF_MAP_POLICY_CIDR_V4, BPF_MAP_POLICY_CIDR_V6, BPF_MAP_POLICY_INDEX, BPF_MAP_POLICY_RULESET,
    BPF_MAP_ROUTER_V4, BPF_MAP_SERVICES_V4, BPF_MAP_SERVICES_V6, BPF_MESH_FS_DIR,
    BPF_MESH_LINKS_DIR, BPF_MESH_MAPS_DIR, BPF_MESH_PROG_DIR, BPF_PROGRAM_CGROUP_CONNECT_V4,
    BPF_PROGRAM_EGRESS_TC, BPF_PROGRAM_INGRESS_TC, BPF_PROGRAM_NODEPORT_EGRESS_TC,
    BPF_PROGRAM_NODEPORT_INGRESS_TC, BPF_PROGRAM_VXLAN_NODE_INGRESS_TC,
    BPF_PROGRAM_VXLAN_VETH_EGRESS_TC, BpfNamePath,
};

use crate::{Result, bpf::ip::LpmKeyNetwork};

pub type IdentityMapV4 = LpmTrie<MapData, u32, IdentityId>;
pub type IdentityMapV6 = LpmTrie<MapData, u128, IdentityId>;

pub(crate) const POLICY_MAPS_LIST: [BpfNamePath; 7] = [
    BPF_MAP_IDENTITY_V4,
    BPF_MAP_IDENTITY_V6,
    BPF_MAP_CONNTRACK_V4,
    BPF_MAP_POLICY_INDEX,
    BPF_MAP_POLICY_RULESET,
    BPF_MAP_POLICY_CIDR_V4,
    BPF_MAP_POLICY_CIDR_V6,
];

pub(crate) const SERVICE_MAPS_LIST: [BpfNamePath; 9] = [
    BPF_MAP_SERVICES_V4,
    BPF_MAP_SERVICES_V6,
    BPF_MAP_ENDPOINTS_V4,
    BPF_MAP_ENDPOINTS_V6,
    BPF_MAP_NODEPORT_LOCAL_ADDRS_V4,
    BPF_MAP_NODEPORT_SERVICES_V4,
    BPF_MAP_NODEPORT_REV_NAT_V4,
    BPF_MAP_NODEPORT_CONNTRACK_V4,
    BPF_MAP_ROUTER_V4,
];

pub(crate) const PROG_LIST: [BpfNamePath; 5] = [
    BPF_PROGRAM_CGROUP_CONNECT_V4,
    BPF_PROGRAM_INGRESS_TC,
    BPF_PROGRAM_EGRESS_TC,
    BPF_PROGRAM_NODEPORT_INGRESS_TC,
    BPF_PROGRAM_NODEPORT_EGRESS_TC,
];

pub(crate) const VXLAN_PROG_LIST: [BpfNamePath; 2] = [
    BPF_PROGRAM_VXLAN_VETH_EGRESS_TC,
    BPF_PROGRAM_VXLAN_NODE_INGRESS_TC,
];

pub trait BpfMap {
    type Key;
    type Value;
    type KeyOutput;
    fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<()>;
    fn delete(&mut self, key: &Self::Key) -> Result<()>;
    fn get(&self, key: &Self::Key) -> Result<Self::Value>;
    fn get_state(&self) -> Result<ahash::HashMap<Self::KeyOutput, Self::Value>>;
}

pub trait SharedBpfMap: Send + Sync + 'static {
    type Key;
    type Value;
    type KeyOutput;
    fn update(&self, key: Self::Key, value: Self::Value) -> Result<()>;
    fn delete(&self, key: &Self::Key) -> Result<()>;
    fn get(&self, key: &Self::Key) -> Result<Self::Value>;
    fn get_state(&self) -> Result<ahash::HashMap<Self::KeyOutput, Self::Value>>;
}

pub(crate) fn is_map_not_found_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<MapError>()
        .is_some_and(|map_err| match map_err {
            MapError::KeyNotFound | MapError::ElementNotFound => true,
            MapError::SyscallError(sys_err) => {
                sys_err.io_error.raw_os_error() == Some(libc::ENOENT)
            }
            MapError::IoError(io_err) => io_err.raw_os_error() == Some(libc::ENOENT),
            _ => false,
        })
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
