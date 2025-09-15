use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use ahash::HashMap;
use aya::maps::lpm_trie::Key as LpmKey;
use mesh_cni_api::ip::v1::IpId;
use mesh_cni_common::Id;

use crate::Result;
use crate::bpf::BpfMap;
use crate::kubernetes::Labels;

struct Shared<IP4, IP6>
where
    IP4: BpfMap,
    IP6: BpfMap,
{
    shared: Mutex<State<IP4, IP6>>,
}

// TODO: implement some runner that periodically checks for orphaned records
// as the controller could miss/error on deletes and these values get stuck in
// the map permanently
struct State<IP4, IP6>
where
    IP4: BpfMap,
    IP6: BpfMap,
{
    ip_to_labels_id: HashMap<IpAddr, (Labels, Id)>,
    labels_to_id: HashMap<Labels, Id>,
    ipv4_state: IpBpfStateV4<IP4>,
    ipv6_state: IpBpfStateV6<IP6>,
    id: Id,
}

impl<IP4, IP6> Clone for IpNetworkState<IP4, IP6>
where
    IP4: BpfMap,
    IP6: BpfMap,
{
    fn clone(&self) -> Self {
        let new = Arc::clone(&self.state);
        Self { state: new }
    }
}

pub struct IpNetworkState<IP4, IP6>
where
    IP4: BpfMap,
    IP6: BpfMap,
{
    state: Arc<Shared<IP4, IP6>>,
}

impl<IP4, IP6> IpNetworkState<IP4, IP6>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = Id>,
    IP6: BpfMap<Key = LpmKey<u128>, Value = Id>,
{
    pub fn new(ipv4_map: IP4, ipv6_map: IP6) -> Self {
        let ipv4_state = IpBpfStateV4::new(ipv4_map);
        let ipv6_state = IpBpfStateV6::new(ipv6_map);
        let state = State {
            labels_to_id: HashMap::default(),
            ip_to_labels_id: HashMap::default(),
            // id less than 128 are reserved for cluster specific items
            id: 128,
            ipv4_state,
            ipv6_state,
        };
        let shared = Shared {
            shared: Mutex::new(state),
        };
        Self {
            state: Arc::new(shared),
        }
    }
    // TODO: check if this can error with notifications
    // LpmTrie expects big endian order for comparisons
    pub fn insert(&self, ip: IpAddr, labels: &Labels) -> Result<()> {
        let mut state = self.state.shared.lock().unwrap();
        if let Some((current_labels, _id)) = state.ip_to_labels_id.get(&ip)
            && *current_labels == *labels
        {
            return Ok(());
        }
        let id = state.id;

        match ip {
            IpAddr::V4(ipv4_addr) => state
                .ipv4_state
                .update(LpmKey::new(32, ipv4_addr.to_bits().to_be()), id)?,
            IpAddr::V6(ipv6_addr) => state
                .ipv6_state
                .update(LpmKey::new(128, ipv6_addr.to_bits().to_be()), id)?,
        };
        let _ = state.labels_to_id.insert(labels.clone(), id);
        let _ = state.ip_to_labels_id.insert(ip, (labels.to_owned(), id));

        state.id += 1;

        Ok(())
    }

    // LpmTrie expects big endian order for comparisons
    pub fn delete(&self, ip: IpAddr) -> Result<()> {
        let mut state = self.state.shared.lock().unwrap();
        match ip {
            IpAddr::V4(ipv4_addr) => state
                .ipv4_state
                .delete(&LpmKey::new(32, ipv4_addr.to_bits().to_be()))?,
            IpAddr::V6(ipv6_addr) => state
                .ipv6_state
                .delete(&LpmKey::new(128, ipv6_addr.to_bits().to_be()))?,
        }
        let labels_id = state.ip_to_labels_id.remove(&ip);
        if let Some((labels, _id)) = labels_id {
            state.labels_to_id.remove(&labels);
        };
        Ok(())
    }

    pub fn get_id_from_labels(&self, labels: &Labels) -> Option<Id> {
        let state = self.state.shared.lock().unwrap();
        state.labels_to_id.get(labels).cloned()
    }
    pub fn get_ip_labels_id(&self) -> Vec<IpId> {
        let state = self.state.shared.lock().unwrap();
        state
            .ip_to_labels_id
            .iter()
            .map(|(ip, (labels, id))| IpId {
                ip: ip.to_string(),
                labels: labels.to_hashmap(),
                id: *id as u32,
            })
            .collect()
    }
}

pub struct IpBpfStateV4<M>
where
    M: BpfMap,
{
    cache: ahash::HashMap<IpNetwork, Id>,
    bpf_map: M,
}

impl<M> IpBpfStateV4<M>
where
    M: BpfMap<Key = LpmKey<u32>, Value = Id>,
{
    pub fn new(bpf_map: M) -> Self {
        let cache = ahash::HashMap::default();
        Self { cache, bpf_map }
    }

    pub fn update(&mut self, key: M::Key, value: M::Value) -> Result<()> {
        if let Some(current) = self.cache.get(&key.into())
            && *current == value
        {
            return Ok(());
        };
        match self.bpf_map.update(key, value) {
            Ok(_) => {
                self.cache.insert(key.into(), value);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn delete(&mut self, key: &M::Key) -> Result<()> {
        match self.bpf_map.delete(key) {
            Ok(_) => {
                let key = IpNetwork::from(*key);
                self.cache.remove(&key);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

pub struct IpBpfStateV6<M>
where
    M: BpfMap,
{
    cache: ahash::HashMap<IpNetwork, Id>,
    bpf_map: M,
}

impl<M> IpBpfStateV6<M>
where
    M: BpfMap<Key = LpmKey<u128>, Value = Id>,
{
    pub fn new(bpf_map: M) -> Self {
        let cache = ahash::HashMap::default();
        Self { cache, bpf_map }
    }

    pub fn update(&mut self, key: M::Key, value: M::Value) -> Result<()> {
        if let Some(current) = self.cache.get(&key.into())
            && *current == value
        {
            return Ok(());
        };
        match self.bpf_map.update(key, value) {
            Ok(_) => {
                self.cache.insert(key.into(), value);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn delete(&mut self, key: &M::Key) -> Result<()> {
        match self.bpf_map.delete(key) {
            Ok(_) => {
                let key = IpNetwork::from(*key);
                self.cache.remove(&key);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum IpNetwork {
    V4(IpNetworkV4),
    V6(IpNetworkV6),
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct IpNetworkV4 {
    pub ip: Ipv4Addr,
    pub mask: u32,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct IpNetworkV6 {
    pub ip: Ipv6Addr,
    pub mask: u32,
}

impl From<LpmKey<u32>> for IpNetwork {
    fn from(value: LpmKey<u32>) -> Self {
        IpNetwork::V4(IpNetworkV4 {
            ip: Ipv4Addr::from_bits(value.data()),
            mask: value.prefix_len(),
        })
    }
}

impl From<LpmKey<u128>> for IpNetwork {
    fn from(value: LpmKey<u128>) -> Self {
        IpNetwork::V6(IpNetworkV6 {
            ip: Ipv6Addr::from_bits(value.data()),
            mask: value.prefix_len(),
        })
    }
}

impl From<IpNetworkV4> for LpmKey<u32> {
    fn from(value: IpNetworkV4) -> Self {
        Self::new(value.mask, value.ip.to_bits())
    }
}

impl From<IpNetworkV6> for LpmKey<u128> {
    fn from(value: IpNetworkV6) -> Self {
        Self::new(value.mask, value.ip.to_bits())
    }
}
