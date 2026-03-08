use std::sync::{Arc, Mutex};

use aya::maps::lpm_trie::Key as LpmKey;
use ipnetwork::IpNetwork;
use mesh_cni_ebpf_common::IdentityId;
use mesh_cni_identity_controller::{IdentityReader, IdentityWriter};

use crate::{
    Result,
    bpf::{BpfMap, ip::LpmKeyNetwork, is_map_not_found_error},
};

struct Shared<IP4, IP6>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = IdentityId, KeyOutput = IpNetwork>,
    IP6: BpfMap<Key = LpmKey<u128>, Value = IdentityId, KeyOutput = IpNetwork>,
{
    shared: Mutex<State<IP4, IP6>>,
}

// TODO: implement some runner that periodically checks for orphaned records
// as the controller could miss/error on deletes and these values get stuck in
// the map permanently
struct State<IP4, IP6>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = IdentityId, KeyOutput = IpNetwork>,
    IP6: BpfMap<Key = LpmKey<u128>, Value = IdentityId, KeyOutput = IpNetwork>,
{
    ipv4_state: IpBpfStateV4<IP4>,
    ipv6_state: IpBpfStateV6<IP6>,
}

impl<IP4, IP6> Clone for IpNetworkState<IP4, IP6>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = IdentityId, KeyOutput = IpNetwork>,
    IP6: BpfMap<Key = LpmKey<u128>, Value = IdentityId, KeyOutput = IpNetwork>,
{
    fn clone(&self) -> Self {
        let new = Arc::clone(&self.state);
        Self { state: new }
    }
}

pub struct IpNetworkState<IP4, IP6>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = IdentityId, KeyOutput = IpNetwork>,
    IP6: BpfMap<Key = LpmKey<u128>, Value = IdentityId, KeyOutput = IpNetwork>,
{
    state: Arc<Shared<IP4, IP6>>,
}

impl<IP4, IP6> IpNetworkState<IP4, IP6>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = IdentityId, KeyOutput = IpNetwork>,
    IP6: BpfMap<Key = LpmKey<u128>, Value = IdentityId, KeyOutput = IpNetwork>,
{
    pub fn try_new(ipv4_map: IP4, ipv6_map: IP6) -> Result<Self> {
        let ipv4_state = IpBpfStateV4::try_new(ipv4_map)?;
        let ipv6_state = IpBpfStateV6::try_new(ipv6_map)?;
        let state = State {
            ipv4_state,
            ipv6_state,
        };
        let shared = Shared {
            shared: Mutex::new(state),
        };
        Ok(Self {
            state: Arc::new(shared),
        })
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
    pub fn delete_network(&self, ip_net: IpNetwork) -> Result<()> {
        let mut state = self.state.shared.lock().unwrap();
        match ip_net {
            IpNetwork::V4(ipv4_network) => state.ipv4_state.delete(&LpmKey::new(
                ipv4_network.prefix() as u32,
                ipv4_network.ip().to_bits().to_be(),
            ))?,
            IpNetwork::V6(ipv6_network) => state.ipv6_state.delete(&LpmKey::new(
                ipv6_network.prefix() as u32,
                ipv6_network.ip().to_bits().to_be(),
            ))?,
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

impl<IP4, IP6> IdentityWriter for IpNetworkState<IP4, IP6>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = IdentityId, KeyOutput = IpNetwork>,
    IP6: BpfMap<Key = LpmKey<u128>, Value = IdentityId, KeyOutput = IpNetwork>,
{
    fn upsert_identity(
        &self,
        key: IpNetwork,
        value: IdentityId,
    ) -> mesh_cni_identity_controller::Result<()> {
        self.update(key, value)
            .map_err(|e| mesh_cni_identity_controller::Error::OpError(e.to_string()))
    }

    fn remove_identity(&self, key: IpNetwork) -> mesh_cni_identity_controller::Result<()> {
        self.delete_network(key)
            .map_err(|e| mesh_cni_identity_controller::Error::OpError(e.to_string()))
    }
}

impl<IP4, IP6> IdentityReader for IpNetworkState<IP4, IP6>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = IdentityId, KeyOutput = IpNetwork>,
    IP6: BpfMap<Key = LpmKey<u128>, Value = IdentityId, KeyOutput = IpNetwork>,
{
    fn identity_state(&self) -> mesh_cni_identity_controller::Result<Vec<(IpNetwork, IdentityId)>> {
        Ok(self.state())
    }
}

pub struct IpBpfStateV4<M>
where
    M: BpfMap<Key = LpmKey<u32>, Value = IdentityId, KeyOutput = IpNetwork>,
{
    cache: ahash::HashMap<IpNetwork, IdentityId>,
    bpf_map: M,
}

impl<M> IpBpfStateV4<M>
where
    M: BpfMap<Key = LpmKey<u32>, Value = IdentityId, KeyOutput = IpNetwork>,
{
    pub fn try_new(bpf_map: M) -> Result<Self> {
        let cache = bpf_map.get_state()?;
        Ok(Self { cache, bpf_map })
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
            Err(err) if is_map_not_found_error(&err) => {
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
    M: BpfMap<Key = LpmKey<u128>, Value = IdentityId, KeyOutput = IpNetwork>,
{
    cache: ahash::HashMap<IpNetwork, IdentityId>,
    bpf_map: M,
}

impl<M> IpBpfStateV6<M>
where
    M: BpfMap<Key = LpmKey<u128>, Value = IdentityId, KeyOutput = IpNetwork>,
{
    pub fn try_new(bpf_map: M) -> Result<Self> {
        let cache = bpf_map.get_state()?;
        Ok(Self { cache, bpf_map })
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
            Err(err) if is_map_not_found_error(&err) => {
                let network = <u128 as LpmKeyNetwork>::key_to_network(*key);
                self.cache.remove(&network);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}
