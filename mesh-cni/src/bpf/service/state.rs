use std::{
    ops::Range,
    sync::{Arc, Mutex},
};

use ahash::{HashMap, HashMapExt};
use anyhow::anyhow;
use aya::maps::MapError;
use mesh_cni_ebpf_common::{
    Id,
    service::{
        EndpointKey, EndpointValue, EndpointValueV4, EndpointValueV6, NodePortKey, ServiceKey,
        ServiceKeyV4, ServiceKeyV6, ServiceValue,
    },
};
use mesh_cni_service_bpf_controller::{
    Error as ControllerError, NodePortReader, NodePortWriter, ServiceReader, ServiceWriter,
};
use tracing::warn;

use crate::{Result, bpf::BpfMap};

fn is_map_not_found_error(err: &anyhow::Error) -> bool {
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

pub trait ServiceMapStore {
    type SKey: std::hash::Hash + std::cmp::Eq + Copy;
    fn update_service(&mut self, key: Self::SKey, value: ServiceValue) -> Result<()>;
    fn delete_service(&mut self, key: &Self::SKey) -> Result<()>;
    fn get_cached_service(&self, key: &Self::SKey) -> Option<&ServiceValue>;
    fn insert_cached_service(&mut self, key: Self::SKey, value: ServiceValue);
    fn remove_cached_service(&mut self, key: &Self::SKey);
    fn service_cache(&self) -> &ahash::HashMap<Self::SKey, ServiceValue>;
    fn service_map_state(&self) -> Result<ahash::HashMap<Self::SKey, ServiceValue>>;
}

pub trait EndpointMapStore {
    type EValue: std::cmp::PartialEq + Copy;
    fn update_endpoint(&mut self, key: EndpointKey, value: Self::EValue) -> Result<()>;
    fn delete_endpoint(&mut self, key: &EndpointKey) -> Result<()>;
    fn insert_cached_endpoint(&mut self, key: EndpointKey, value: Self::EValue);
    fn remove_cached_endpoint(&mut self, key: &EndpointKey);
    fn endpoint_cache(&self) -> &ahash::HashMap<EndpointKey, Self::EValue>;
    fn endpoint_map_state(&self) -> Result<ahash::HashMap<EndpointKey, Self::EValue>>;
}

fn insert_endpoints<S>(
    store: &mut S,
    service_value: &ServiceValue,
    endpoints: Vec<&S::EValue>,
) -> Result<()>
where
    S: EndpointMapStore,
{
    for (position, ep) in endpoints.iter().enumerate() {
        let position =
            u16::try_from(position).map_err(|e| anyhow!("failed to convert position: {}", e))?;
        let endpoint_key = EndpointKey::new(service_value.id, position);
        store.update_endpoint(endpoint_key, **ep)?;
        store.insert_cached_endpoint(endpoint_key, **ep);
    }
    Ok(())
}

fn delete_endpoints<S>(store: &mut S, service_value: &ServiceValue, range: Range<u16>) -> Result<()>
where
    S: EndpointMapStore,
{
    for idx in range {
        let endpoint_key = EndpointKey::new(service_value.id, idx);
        store.delete_endpoint(&endpoint_key)?;
        store.remove_cached_endpoint(&endpoint_key);
    }
    Ok(())
}

fn update_service_with_endpoints<S>(
    store: &mut S,
    key: S::SKey,
    endpoints: Vec<&S::EValue>,
    mut id: Id,
) -> Result<Id>
where
    S: ServiceMapStore + EndpointMapStore,
{
    let new_count = u16::try_from(endpoints.len()).map_err(|e| anyhow!(e.to_string()))?;

    let Some(current_service_value) = store.get_cached_service(&key).copied() else {
        let service_value = ServiceValue {
            id,
            count: new_count,
        };
        store.update_service(key, service_value)?;
        store.insert_cached_service(key, service_value);
        insert_endpoints(store, &service_value, endpoints)?;
        id += 1;
        return Ok(id);
    };

    let new_service_value = ServiceValue {
        id: current_service_value.id,
        count: new_count,
    };

    if new_count > current_service_value.count {
        // Ensure new endpoint slots are populated before datapath can select them.
        insert_endpoints(store, &new_service_value, endpoints)?;
        store.update_service(key, new_service_value)?;
    } else {
        store.update_service(key, new_service_value)?;
        insert_endpoints(store, &new_service_value, endpoints)?;

        if current_service_value.count > new_count {
            delete_endpoints(
                store,
                &new_service_value,
                new_count..current_service_value.count,
            )?;
        }
    }
    store.insert_cached_service(key, new_service_value);

    Ok(current_service_value.id)
}

fn remove_service_with_endpoints<S>(store: &mut S, key: &S::SKey) -> Result<()>
where
    S: ServiceMapStore + EndpointMapStore,
{
    let Some(service_value) = store.get_cached_service(key).copied() else {
        return Ok(());
    };

    delete_endpoints(store, &service_value, 0..service_value.count)?;
    store.delete_service(key)?;
    store.remove_cached_service(key);
    Ok(())
}

pub struct ServiceEndpoint<S, E, SK, EV>
where
    S: BpfMap,
    E: BpfMap,
    SK: std::hash::Hash + std::cmp::Eq + Clone + Copy,
    EV: Clone + std::cmp::PartialEq + Copy,
{
    service_cache: ahash::HashMap<SK, ServiceValue>,
    service_map: S,
    endpoint_cache: ahash::HashMap<EndpointKey, EV>,
    endpoint_map: E,
}

impl<S, E, SK, EV> ServiceEndpoint<S, E, SK, EV>
where
    S: BpfMap,
    E: BpfMap,
    SK: std::hash::Hash + std::cmp::Eq + Clone + Copy,
    EV: Clone + std::cmp::PartialEq + Copy,
{
    pub fn new(service_map: S, endpoint_map: E) -> Result<Self>
    where
        S: BpfMap<Key = SK, Value = ServiceValue, KeyOutput = SK>,
        E: BpfMap<Key = EndpointKey, Value = EV, KeyOutput = EndpointKey>,
    {
        let service_cache = service_map.get_state()?;
        let endpoint_cache = endpoint_map.get_state()?;
        Ok(Self {
            service_cache,
            service_map,
            endpoint_cache,
            endpoint_map,
        })
    }
    pub fn update(&mut self, key: SK, value: Vec<&EV>, id: Id) -> Result<Id>
    where
        Self: ServiceMapStore<SKey = SK> + EndpointMapStore<EValue = EV>,
    {
        update_service_with_endpoints(self, key, value, id)
    }

    pub fn remove(&mut self, key: &SK) -> Result<()>
    where
        Self: ServiceMapStore<SKey = SK> + EndpointMapStore<EValue = EV>,
    {
        remove_service_with_endpoints(self, key)
    }

    pub fn get_from_cache(&self, key: &SK) -> Option<&ServiceValue>
    where
        Self: ServiceMapStore<SKey = SK>,
    {
        self.get_cached_service(key)
    }
}

impl<S, E, SK, EV> ServiceMapStore for ServiceEndpoint<S, E, SK, EV>
where
    S: BpfMap<Key = SK, Value = ServiceValue, KeyOutput = SK>,
    E: BpfMap<Key = EndpointKey, Value = EV, KeyOutput = EndpointKey>,
    SK: std::hash::Hash + std::cmp::Eq + Clone + Copy,
    EV: std::cmp::PartialEq + Copy,
{
    type SKey = SK;

    fn update_service(&mut self, key: Self::SKey, value: ServiceValue) -> Result<()> {
        self.service_map.update(key, value)
    }

    fn delete_service(&mut self, key: &Self::SKey) -> Result<()> {
        self.service_map.delete(key)
    }

    fn get_cached_service(&self, key: &Self::SKey) -> Option<&ServiceValue> {
        self.service_cache.get(key)
    }

    fn insert_cached_service(&mut self, key: Self::SKey, value: ServiceValue) {
        self.service_cache.insert(key, value);
    }

    fn remove_cached_service(&mut self, key: &Self::SKey) {
        self.service_cache.remove(key);
    }

    fn service_cache(&self) -> &ahash::HashMap<Self::SKey, ServiceValue> {
        &self.service_cache
    }

    fn service_map_state(&self) -> Result<ahash::HashMap<Self::SKey, ServiceValue>> {
        let mut map = HashMap::default();
        let state = self.service_map.get_state()?;
        for (k, v) in state.iter() {
            map.insert(*k, *v);
        }
        Ok(map)
    }
}

impl<S, E, SK, EV> EndpointMapStore for ServiceEndpoint<S, E, SK, EV>
where
    S: BpfMap<Key = SK, Value = ServiceValue, KeyOutput = SK>,
    E: BpfMap<Key = EndpointKey, Value = EV, KeyOutput = EndpointKey>,
    SK: std::hash::Hash + std::cmp::Eq + Clone + Copy,
    EV: std::cmp::PartialEq + Copy,
{
    type EValue = EV;

    fn update_endpoint(&mut self, key: EndpointKey, value: Self::EValue) -> Result<()> {
        self.endpoint_map.update(key, value)
    }

    fn delete_endpoint(&mut self, key: &EndpointKey) -> Result<()> {
        self.endpoint_map.delete(key)
    }

    fn insert_cached_endpoint(&mut self, key: EndpointKey, value: Self::EValue) {
        self.endpoint_cache.insert(key, value);
    }

    fn remove_cached_endpoint(&mut self, key: &EndpointKey) {
        self.endpoint_cache.remove(key);
    }

    fn endpoint_cache(&self) -> &ahash::HashMap<EndpointKey, Self::EValue> {
        &self.endpoint_cache
    }

    fn endpoint_map_state(&self) -> Result<ahash::HashMap<EndpointKey, Self::EValue>> {
        let mut map = HashMap::default();
        let state = self.endpoint_map.get_state()?;
        for (k, v) in state.iter() {
            map.insert(*k, *v);
        }
        Ok(map)
    }
}

struct Shared<SE4, SE6, NP>
where
    SE4: ServiceMapStore + EndpointMapStore,
    SE6: ServiceMapStore + EndpointMapStore,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
{
    state: Mutex<State<SE4, SE6, NP>>,
}

struct State<SE4, SE6, NP>
where
    SE4: ServiceMapStore + EndpointMapStore,
    SE6: ServiceMapStore + EndpointMapStore,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
{
    service_endpoint_v4: SE4,
    service_endpoint_v6: SE6,
    nodeport_cache: ahash::HashMap<NodePortKey, ServiceKeyV4>,
    nodeport_map: NP,
    id: Id,
}

pub struct ServiceEndpointState<SE4, SE6, NP>
where
    SE4: ServiceMapStore<SKey = ServiceKeyV4> + EndpointMapStore<EValue = EndpointValueV4>,
    SE6: ServiceMapStore<SKey = ServiceKeyV6> + EndpointMapStore<EValue = EndpointValueV6>,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
{
    shared: Arc<Shared<SE4, SE6, NP>>,
}

impl<SE4, SE6, NP> Clone for ServiceEndpointState<SE4, SE6, NP>
where
    SE4: ServiceMapStore<SKey = ServiceKeyV4> + EndpointMapStore<EValue = EndpointValueV4>,
    SE6: ServiceMapStore<SKey = ServiceKeyV6> + EndpointMapStore<EValue = EndpointValueV6>,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
{
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<SE4, SE6, NP> ServiceEndpointState<SE4, SE6, NP>
where
    SE4: ServiceMapStore<SKey = ServiceKeyV4> + EndpointMapStore<EValue = EndpointValueV4>,
    SE6: ServiceMapStore<SKey = ServiceKeyV6> + EndpointMapStore<EValue = EndpointValueV6>,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
{
    pub(crate) fn new(
        service_endpoint_v4: SE4,
        service_endpoint_v6: SE6,
        nodeport_map: NP,
    ) -> Result<Self> {
        let nodeport_cache = nodeport_map.get_state()?;
        let next_id = {
            let max_id_v4 = service_endpoint_v4
                .service_cache()
                .values()
                .map(|service_value| service_value.id)
                .max();
            let max_id_v6 = service_endpoint_v6
                .service_cache()
                .values()
                .map(|service_value| service_value.id)
                .max();
            let max_existing = max_id_v4.into_iter().chain(max_id_v6).max();
            std::cmp::max(
                128,
                max_existing.map(|id| id.saturating_add(1)).unwrap_or(128),
            )
        };
        let state = State {
            service_endpoint_v4,
            service_endpoint_v6,
            nodeport_cache,
            nodeport_map,
            id: next_id,
        };

        let shared = Shared {
            state: Mutex::new(state),
        };
        let shared = Arc::new(shared);

        Ok(Self { shared })
    }

    pub(crate) fn update(&self, key: ServiceKey, value: Vec<EndpointValue>) -> Result<()> {
        let mut state = self.shared.state.lock().unwrap();
        let current_id = state.id;
        let new_id = match key {
            ServiceKey::V4(service_key_v4) => {
                let endpoints = value
                    .iter()
                    .filter_map(|e| {
                        if let EndpointValue::V4(e) = e {
                            Some(e)
                        } else {
                            None
                        }
                    })
                    .collect();
                update_service_with_endpoints(
                    &mut state.service_endpoint_v4,
                    service_key_v4,
                    endpoints,
                    current_id,
                )?
            }
            ServiceKey::V6(service_key_v6) => {
                let endpoints = value
                    .iter()
                    .filter_map(|e| {
                        if let EndpointValue::V6(e) = e {
                            Some(e)
                        } else {
                            None
                        }
                    })
                    .collect();
                update_service_with_endpoints(
                    &mut state.service_endpoint_v6,
                    service_key_v6,
                    endpoints,
                    current_id,
                )?
            }
        };
        if new_id > current_id {
            state.id += 1
        }
        Ok(())
    }

    pub(crate) fn remove(&self, key: &ServiceKey) -> Result<()> {
        let mut state = self.shared.state.lock().unwrap();
        match key {
            ServiceKey::V4(service_key_v4) => {
                remove_service_with_endpoints(&mut state.service_endpoint_v4, service_key_v4)?;
            }
            ServiceKey::V6(service_key_v6) => {
                remove_service_with_endpoints(&mut state.service_endpoint_v6, service_key_v6)?;
            }
        }
        Ok(())
    }

    pub(crate) fn update_nodeport(&self, key: NodePortKey, service_key: ServiceKey) -> Result<()> {
        let mut state = self.shared.state.lock().unwrap();
        let service_key_v4 = match service_key {
            ServiceKey::V4(service_key_v4) => service_key_v4,
            ServiceKey::V6(_) => {
                return Err(anyhow!("nodeport map only supports ipv4 service keys"));
            }
        };
        state.nodeport_map.update(key, service_key_v4)?;
        state.nodeport_cache.insert(key, service_key_v4);
        Ok(())
    }

    pub(crate) fn remove_nodeport(&self, key: &NodePortKey) -> Result<()> {
        let mut state = self.shared.state.lock().unwrap();
        match state.nodeport_map.delete(key) {
            Ok(()) => {
                state.nodeport_cache.remove(key);
                Ok(())
            }
            Err(err) if is_map_not_found_error(&err) => {
                state.nodeport_cache.remove(key);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    pub(crate) fn nodeport_state_from_cache(
        &self,
    ) -> Result<ahash::HashMap<NodePortKey, ServiceKey>> {
        let state = self.shared.state.lock().unwrap();
        Ok(state
            .nodeport_cache
            .iter()
            .map(|(nodeport_key, service_key)| (*nodeport_key, ServiceKey::V4(*service_key)))
            .collect())
    }

    pub(crate) fn state_from_cache(
        &self,
    ) -> Result<ahash::HashMap<ServiceKey, Vec<EndpointValue>>> {
        let state = self.shared.state.lock().unwrap();
        let mut map = ahash::HashMap::new();
        let cached_service_v4 = state.service_endpoint_v4.service_cache();
        let cached_endpoints_v4 = state.service_endpoint_v4.endpoint_cache();
        for (k, v) in cached_service_v4 {
            let mut endpoints = vec![];
            let count = v.count;
            for idx in 0..count {
                let Some(endpoint_value) = cached_endpoints_v4.get(&EndpointKey::new(v.id, idx))
                else {
                    warn!("did not find endpoints with id {} and idx {}", v.id, idx);
                    continue;
                };
                endpoints.push(EndpointValue::V4(endpoint_value.to_owned()));
            }
            map.insert(ServiceKey::V4(k.to_owned()), endpoints);
        }
        let cached_service_v6 = state.service_endpoint_v6.service_cache();
        let cached_endpoints_v6 = state.service_endpoint_v6.endpoint_cache();
        for (k, v) in cached_service_v6 {
            let mut endpoints = vec![];
            let count = v.count;
            for idx in 0..count {
                let Some(endpoint_value) = cached_endpoints_v6.get(&EndpointKey::new(v.id, idx))
                else {
                    warn!("did not find endpoints with id {} and idx {}", v.id, idx);
                    continue;
                };
                endpoints.push(EndpointValue::V6(endpoint_value.to_owned()));
            }
            map.insert(ServiceKey::V6(k.to_owned()), endpoints);
        }
        Ok(map)
    }
}

impl<SE4, SE6, NP> ServiceWriter for ServiceEndpointState<SE4, SE6, NP>
where
    SE4: ServiceMapStore<SKey = ServiceKeyV4> + EndpointMapStore<EValue = EndpointValueV4>,
    SE6: ServiceMapStore<SKey = ServiceKeyV6> + EndpointMapStore<EValue = EndpointValueV6>,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
{
    fn upsert_service(
        &self,
        key: ServiceKey,
        value: Vec<EndpointValue>,
    ) -> std::result::Result<(), ControllerError> {
        ServiceEndpointState::update(self, key, value)
            .map_err(|e| ControllerError::BpfState(e.to_string()))
    }

    fn remove_service(&self, key: &ServiceKey) -> std::result::Result<(), ControllerError> {
        ServiceEndpointState::remove(self, key)
            .map_err(|e| ControllerError::BpfState(e.to_string()))
    }
}

impl<SE4, SE6, NP> NodePortWriter for ServiceEndpointState<SE4, SE6, NP>
where
    SE4: ServiceMapStore<SKey = ServiceKeyV4> + EndpointMapStore<EValue = EndpointValueV4>,
    SE6: ServiceMapStore<SKey = ServiceKeyV6> + EndpointMapStore<EValue = EndpointValueV6>,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
{
    fn upsert_nodeport(
        &self,
        key: NodePortKey,
        service_key: ServiceKey,
    ) -> std::result::Result<(), ControllerError> {
        ServiceEndpointState::update_nodeport(self, key, service_key)
            .map_err(|e| ControllerError::BpfState(e.to_string()))
    }

    fn remove_nodeport(&self, key: &NodePortKey) -> std::result::Result<(), ControllerError> {
        ServiceEndpointState::remove_nodeport(self, key)
            .map_err(|e| ControllerError::BpfState(e.to_string()))
    }
}

impl<SE4, SE6, NP> ServiceReader for ServiceEndpointState<SE4, SE6, NP>
where
    SE4: ServiceMapStore<SKey = ServiceKeyV4> + EndpointMapStore<EValue = EndpointValueV4>,
    SE6: ServiceMapStore<SKey = ServiceKeyV6> + EndpointMapStore<EValue = EndpointValueV6>,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
{
    fn service_state(
        &self,
    ) -> std::result::Result<ahash::HashMap<ServiceKey, Vec<EndpointValue>>, ControllerError> {
        ServiceEndpointState::state_from_cache(self)
            .map_err(|e| ControllerError::BpfState(e.to_string()))
    }
}

impl<SE4, SE6, NP> NodePortReader for ServiceEndpointState<SE4, SE6, NP>
where
    SE4: ServiceMapStore<SKey = ServiceKeyV4> + EndpointMapStore<EValue = EndpointValueV4>,
    SE6: ServiceMapStore<SKey = ServiceKeyV6> + EndpointMapStore<EValue = EndpointValueV6>,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
{
    fn nodeport_state(
        &self,
    ) -> std::result::Result<ahash::HashMap<NodePortKey, ServiceKey>, ControllerError> {
        ServiceEndpointState::nodeport_state_from_cache(self)
            .map_err(|e| ControllerError::BpfState(e.to_string()))
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use ahash::HashMap;
    use mesh_cni_ebpf_common::KubeProtocol;

    use super::*;

    fn new_service_endpoint() -> ServiceEndpoint<
        HashMap<ServiceKeyV4, ServiceValue>,
        HashMap<EndpointKey, EndpointValueV4>,
        ServiceKeyV4,
        EndpointValueV4,
    > {
        let service_map: HashMap<ServiceKeyV4, ServiceValue> = HashMap::default();
        let endpoint_map: HashMap<EndpointKey, EndpointValueV4> = HashMap::default();
        ServiceEndpoint::new(service_map, endpoint_map).unwrap()
    }

    fn new_service_endpoint_state() -> ServiceEndpointState<
        ServiceEndpoint<
            HashMap<ServiceKeyV4, ServiceValue>,
            HashMap<EndpointKey, EndpointValueV4>,
            ServiceKeyV4,
            EndpointValueV4,
        >,
        ServiceEndpoint<
            HashMap<ServiceKeyV6, ServiceValue>,
            HashMap<EndpointKey, EndpointValueV6>,
            ServiceKeyV6,
            EndpointValueV6,
        >,
        HashMap<NodePortKey, ServiceKeyV4>,
    > {
        let service_v4 = ServiceEndpoint::new(HashMap::default(), HashMap::default()).unwrap();
        let service_v6 = ServiceEndpoint::new(HashMap::default(), HashMap::default()).unwrap();
        let nodeport = HashMap::default();
        ServiceEndpointState::new(service_v4, service_v6, nodeport).unwrap()
    }

    #[test]
    fn test_update_with_same_key() -> crate::Result<()> {
        let mut service_endpoint = new_service_endpoint();

        let service_key = ServiceKeyV4::new(
            Ipv4Addr::new(192, 168, 0, 1).to_bits(),
            80,
            KubeProtocol::Tcp as u8,
        );
        let endpoint_one = EndpointValueV4 {
            ip: Ipv4Addr::new(10, 0, 0, 1).to_bits(),
            port: 8080,
            _protocol: KubeProtocol::Tcp as u8,
        };
        let endpoint_two = EndpointValueV4 {
            ip: Ipv4Addr::new(10, 0, 0, 2).to_bits(),
            port: 8080,
            _protocol: KubeProtocol::Tcp as u8,
        };
        let mut endpoints = vec![&endpoint_one];
        let initial_id = 0;
        let first_id = service_endpoint.update(service_key, endpoints.clone(), initial_id)?;
        assert_ne!(initial_id, first_id);

        endpoints.push(&endpoint_two);
        let second_id = service_endpoint.update(service_key, endpoints.clone(), first_id)?;

        assert_eq!(initial_id, second_id);

        Ok(())
    }

    #[test]
    fn update_existing_service_changes_count() -> crate::Result<()> {
        let mut service_endpoint = new_service_endpoint();

        let service_key = ServiceKeyV4::new(
            Ipv4Addr::new(192, 168, 0, 1).to_bits(),
            80,
            KubeProtocol::Tcp as u8,
        );
        let endpoint_one = EndpointValueV4 {
            ip: Ipv4Addr::new(10, 0, 0, 1).to_bits(),
            port: 8080,
            _protocol: KubeProtocol::Tcp as u8,
        };

        let next_id = service_endpoint.update(service_key, vec![&endpoint_one], 0)?;
        assert_eq!(
            service_endpoint.get_from_cache(&service_key).unwrap().count,
            1
        );

        let endpoint_two = EndpointValueV4 {
            ip: Ipv4Addr::new(10, 0, 0, 2).to_bits(),
            port: 8080,
            _protocol: KubeProtocol::Tcp as u8,
        };
        let _ =
            service_endpoint.update(service_key, vec![&endpoint_one, &endpoint_two], next_id)?;
        assert_eq!(
            service_endpoint.get_from_cache(&service_key).unwrap().count,
            2
        );

        let _ = service_endpoint.update(service_key, vec![&endpoint_one], next_id)?;
        assert_eq!(
            service_endpoint.get_from_cache(&service_key).unwrap().count,
            1
        );

        Ok(())
    }

    #[test]
    fn update_nodeport_uses_service_value() -> crate::Result<()> {
        let state = new_service_endpoint_state();
        let service_key = ServiceKey::v4(
            Ipv4Addr::new(10, 96, 0, 10).to_bits(),
            80,
            KubeProtocol::Tcp as u8,
        );
        let endpoint = EndpointValue::V4(EndpointValueV4 {
            ip: Ipv4Addr::new(10, 0, 0, 2).to_bits(),
            port: 8080,
            _protocol: KubeProtocol::Tcp as u8,
        });
        state.update(service_key, vec![endpoint])?;

        let nodeport_key = NodePortKey::new(30080, KubeProtocol::Tcp as u8);
        state.update_nodeport(
            nodeport_key,
            ServiceKey::v4(
                Ipv4Addr::new(10, 96, 0, 10).to_bits(),
                80,
                KubeProtocol::Tcp as u8,
            ),
        )?;
        let nodeport_state = state.nodeport_state_from_cache()?;

        assert!(nodeport_state.contains_key(&nodeport_key));
        Ok(())
    }
}
