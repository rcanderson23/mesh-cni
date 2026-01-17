use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};

use aya::maps::lpm_trie::Key as LpmKey;
use ipnetwork::IpNetwork;
use mesh_cni_ebpf_common::IdentityId;
use mesh_cni_identity_controller::IdentityBpfState;

use crate::{
    Result,
    bpf::{BpfMap, ip::LpmKeyNetwork},
};

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
    ipv4_state: IpBpfStateV4<IP4>,
    ipv6_state: IpBpfStateV6<IP6>,
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
    IP4: BpfMap<Key = LpmKey<u32>, Value = IdentityId>,
    IP6: BpfMap<Key = LpmKey<u128>, Value = IdentityId>,
{
    pub fn new(ipv4_map: IP4, ipv6_map: IP6) -> Self {
        let ipv4_state = IpBpfStateV4::new(ipv4_map);
        let ipv6_state = IpBpfStateV6::new(ipv6_map);
        let state = State {
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
    pub fn update(&self, ip_net: IpNetwork, id: IdentityId) -> Result<()> {
        let mut state = self.state.shared.lock().unwrap();
        match ip_net {
            IpNetwork::V4(ipv4_network) => state.ipv4_state.update(
                LpmKey::new(
                    ipv4_network.prefix() as u32,
                    ipv4_network.ip().to_bits().to_be(),
                ),
                id,
            ),
            IpNetwork::V6(ipv6_network) => state.ipv6_state.update(
                LpmKey::new(
                    ipv6_network.prefix() as u32,
                    ipv6_network.ip().to_bits().to_be(),
                ),
                id,
            ),
        }?;
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
        Ok(())
    }
    pub fn state(&self) -> Vec<(IpNetwork, IdentityId)> {
        let state = self.state.shared.lock().unwrap();
        let mut nets = vec![];
        for (ip_net, id) in state.ipv4_state.cache.iter() {
            nets.push((*ip_net, *id));
        }
        for (ip_net, id) in state.ipv6_state.cache.iter() {
            nets.push((*ip_net, *id));
        }
        nets
    }
}

impl<IP4, IP6> IdentityBpfState for IpNetworkState<IP4, IP6>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = IdentityId>,
    IP6: BpfMap<Key = LpmKey<u128>, Value = IdentityId>,
{
    fn update(
        &self,
        key: IpNetwork,
        value: IdentityId,
    ) -> mesh_cni_identity_controller::Result<()> {
        self.update(key, value)
            .map_err(|e| mesh_cni_identity_controller::Error::OpError(e.to_string()))
    }
}

pub struct IpBpfStateV4<M>
where
    M: BpfMap,
{
    cache: ahash::HashMap<IpNetwork, IdentityId>,
    bpf_map: M,
}

impl<M> IpBpfStateV4<M>
where
    M: BpfMap<Key = LpmKey<u32>, Value = IdentityId>,
{
    pub fn new(bpf_map: M) -> Self {
        let cache = ahash::HashMap::default();
        Self { cache, bpf_map }
    }

    pub fn update(&mut self, key: M::Key, value: M::Value) -> Result<()> {
        let network = <u32 as LpmKeyNetwork>::key_to_network(key);
        if let Some(current) = self.cache.get(&network)
            && *current == value
        {
            return Ok(());
        };
        match self.bpf_map.update(key, value) {
            Ok(_) => {
                self.cache.insert(network, value);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn delete(&mut self, key: &M::Key) -> Result<()> {
        match self.bpf_map.delete(key) {
            Ok(_) => {
                let network = <u32 as LpmKeyNetwork>::key_to_network(*key);
                self.cache.remove(&network);
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
    cache: ahash::HashMap<IpNetwork, IdentityId>,
    bpf_map: M,
}

impl<M> IpBpfStateV6<M>
where
    M: BpfMap<Key = LpmKey<u128>, Value = IdentityId>,
{
    pub fn new(bpf_map: M) -> Self {
        let cache = ahash::HashMap::default();
        Self { cache, bpf_map }
    }

    pub fn update(&mut self, key: M::Key, value: M::Value) -> Result<()> {
        let network = <u128 as LpmKeyNetwork>::key_to_network(key);
        if let Some(current) = self.cache.get(&network)
            && *current == value
        {
            return Ok(());
        };
        match self.bpf_map.update(key, value) {
            Ok(_) => {
                self.cache.insert(network, value);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn delete(&mut self, key: &M::Key) -> Result<()> {
        match self.bpf_map.delete(key) {
            Ok(_) => {
                let network = <u128 as LpmKeyNetwork>::key_to_network(*key);
                self.cache.remove(&network);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}
