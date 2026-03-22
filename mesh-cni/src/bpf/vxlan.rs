use std::sync::{Arc, Mutex};

use ahash::HashMap;
use aya::maps::{LpmTrie, Map, MapData, lpm_trie::Key as LpmKey};
use ipnetwork::IpNetwork;
use mesh_cni_ebpf_common::vxlan::RemoteNodeV4;
use mesh_cni_vxlan_controller::{
    Error as ControllerError, Result as ControllerResult, VxlanRemoteCidrsReader,
    VxlanRemoteCidrsWriter,
};

use crate::{
    Result,
    bpf::{BPF_MAP_VXLAN_REMOTE_CIDRS_V4, BpfMap, is_map_not_found_error},
};

struct Shared<M>
where
    M: BpfMap<Key = LpmKey<u32>, Value = RemoteNodeV4, KeyOutput = IpNetwork>,
{
    shared: Mutex<VxlanStateInner<M>>,
}

struct VxlanStateInner<M>
where
    M: BpfMap<Key = LpmKey<u32>, Value = RemoteNodeV4, KeyOutput = IpNetwork>,
{
    cache: HashMap<IpNetwork, RemoteNodeV4>,
    bpf_map: M,
}

pub struct VxlanRemoteCidrsState<M>
where
    M: BpfMap<Key = LpmKey<u32>, Value = RemoteNodeV4, KeyOutput = IpNetwork>,
{
    state: Arc<Shared<M>>,
}

impl<M> Clone for VxlanRemoteCidrsState<M>
where
    M: BpfMap<Key = LpmKey<u32>, Value = RemoteNodeV4, KeyOutput = IpNetwork>,
{
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<M> VxlanRemoteCidrsState<M>
where
    M: BpfMap<Key = LpmKey<u32>, Value = RemoteNodeV4, KeyOutput = IpNetwork>,
{
    pub fn try_new(bpf_map: M) -> Result<Self> {
        let cache = bpf_map.get_state()?;
        let state = VxlanStateInner { cache, bpf_map };
        let shared = Shared {
            shared: Mutex::new(state),
        };
        Ok(Self {
            state: Arc::new(shared),
        })
    }

    fn upsert(&self, network: IpNetwork, value: RemoteNodeV4) -> Result<()> {
        let IpNetwork::V4(network) = network else {
            anyhow::bail!("ipv6 vxlan remote cidrs are not implemented");
        };

        let key = LpmKey::new(network.prefix() as u32, u32::from(network.ip()).to_be());
        let mut state = self.state.shared.lock().unwrap();
        if let Some(current) = state.cache.get(&IpNetwork::V4(network))
            && *current == value
        {
            return Ok(());
        }

        state.bpf_map.update(key, value)?;
        state.cache.insert(IpNetwork::V4(network), value);
        Ok(())
    }

    fn delete(&self, network: &IpNetwork) -> Result<()> {
        let IpNetwork::V4(network) = network else {
            anyhow::bail!("ipv6 vxlan remote cidrs are not implemented");
        };

        let key = LpmKey::new(network.prefix() as u32, u32::from(network.ip()).to_be());
        let mut state = self.state.shared.lock().unwrap();
        match state.bpf_map.delete(&key) {
            Ok(_) => {
                state.cache.remove(&IpNetwork::V4(*network));
                Ok(())
            }
            Err(err) if is_map_not_found_error(&err) => {
                state.cache.remove(&IpNetwork::V4(*network));
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    fn current_state(&self) -> HashMap<IpNetwork, RemoteNodeV4> {
        self.state.shared.lock().unwrap().cache.clone()
    }
}

impl<M> VxlanRemoteCidrsWriter for VxlanRemoteCidrsState<M>
where
    M: BpfMap<Key = LpmKey<u32>, Value = RemoteNodeV4, KeyOutput = IpNetwork>
        + Send
        + Sync
        + 'static,
{
    fn upsert_vxlan_remote_cidr(
        &self,
        key: IpNetwork,
        value: RemoteNodeV4,
    ) -> ControllerResult<()> {
        self.upsert(key, value)
            .map_err(|e| ControllerError::OpError(e.to_string()))
    }

    fn remove_vxlan_remote_cidr(&self, key: &IpNetwork) -> ControllerResult<()> {
        self.delete(key)
            .map_err(|e| ControllerError::OpError(e.to_string()))
    }
}

impl<M> VxlanRemoteCidrsReader for VxlanRemoteCidrsState<M>
where
    M: BpfMap<Key = LpmKey<u32>, Value = RemoteNodeV4, KeyOutput = IpNetwork>
        + Send
        + Sync
        + 'static,
{
    fn vxlan_remote_cidrs_state(&self) -> ControllerResult<HashMap<IpNetwork, RemoteNodeV4>> {
        Ok(self.current_state())
    }
}

pub type VxlanRemoteCidrsMap = LpmTrie<MapData, u32, RemoteNodeV4>;

pub fn load_remote_cidrs_map() -> Result<VxlanRemoteCidrsMap> {
    let map = MapData::from_pin(BPF_MAP_VXLAN_REMOTE_CIDRS_V4.path())?;
    let map = Map::LpmTrie(map);
    Ok(map.try_into()?)
}
