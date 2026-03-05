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
use mesh_cni_service_bpf_controller::{Error as BpfControllerError, ServiceBpfState};
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

pub trait ServiceEndpointBpfMap {
    type SKey: std::hash::Hash + std::cmp::Eq + Clone;
    type EValue: Clone + std::cmp::PartialEq;
    fn update(&mut self, key: Self::SKey, value: Vec<&Self::EValue>, id: Id) -> Result<Id>;
    fn remove(&mut self, key: &Self::SKey) -> Result<()>;
    fn get_from_cache(&self, key: &Self::SKey) -> Option<&ServiceValue>;
    fn insert_new_service(
        &mut self,
        key: Self::SKey,
        value: Vec<&Self::EValue>,
        id: Id,
    ) -> Result<Id>;
    fn insert_endpoints(
        &mut self,
        service_value: &ServiceValue,
        endpoints: Vec<&Self::EValue>,
    ) -> Result<()>;
    fn delete_endpoints(&mut self, service_value: &ServiceValue, range: Range<u16>) -> Result<()>;
    fn get_service_cache(&self) -> &ahash::HashMap<Self::SKey, ServiceValue>;
    fn get_service_map(&self) -> Result<ahash::HashMap<Self::SKey, ServiceValue>>;
    fn get_endpoint_cache(&self) -> &ahash::HashMap<EndpointKey, Self::EValue>;
    fn get_endpoint_map(&self) -> Result<ahash::HashMap<EndpointKey, Self::EValue>>;
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
    // TODO: create cached maps from bpf maps?
    pub fn new(service_map: S, endpoint_map: E) -> Self {
        Self {
            service_cache: ahash::HashMap::default(),
            service_map,
            endpoint_cache: ahash::HashMap::default(),
            endpoint_map,
        }
    }
}

impl<S, E, SK, EV> ServiceEndpointBpfMap for ServiceEndpoint<S, E, SK, EV>
where
    S: BpfMap<Key = SK, Value = ServiceValue, KeyOutput = SK>,
    E: BpfMap<Key = EndpointKey, Value = EV, KeyOutput = EndpointKey>,
    SK: std::hash::Hash + std::cmp::Eq + Clone + Copy,
    EV: Clone + std::cmp::PartialEq + Copy,
{
    type SKey = SK;
    type EValue = EV;
    fn update(&mut self, key: Self::SKey, value: Vec<&Self::EValue>, id: Id) -> Result<Id> {
        let new_count = u16::try_from(value.len()).map_err(|e| anyhow!(e.to_string()))?;

        let Some(current_service_value) = self.service_cache.get(&key) else {
            return self.insert_new_service(key, value, id);
        };

        let id = current_service_value.id;
        let old_count = current_service_value.count;

        let new_service_value = ServiceValue {
            id,
            count: new_count,
        };

        if new_count > old_count {
            // Ensure new endpoint slots are populated before datapath can select them.
            self.insert_endpoints(&new_service_value, value)?;
            self.service_map.update(key, new_service_value)?;
        } else {
            self.service_map.update(key, new_service_value)?;
            self.insert_endpoints(&new_service_value, value)?;

            if old_count > new_count {
                self.delete_endpoints(&new_service_value, new_count..old_count)?;
            }
        }
        self.service_cache.insert(key, new_service_value);

        Ok(id)
    }

    fn remove(&mut self, key: &Self::SKey) -> Result<()> {
        let Some(service_value) = self.service_cache.get(key) else {
            return Ok(());
        };
        let service_value = *service_value;

        let range = 0..service_value.count;
        self.delete_endpoints(&service_value, range)?;

        self.service_map.delete(key)?;
        self.service_cache.remove(key);
        Ok(())
    }

    fn get_from_cache(&self, key: &Self::SKey) -> Option<&ServiceValue> {
        self.service_cache.get(key)
    }

    fn insert_new_service(
        &mut self,
        key: Self::SKey,
        value: Vec<&Self::EValue>,
        mut id: Id,
    ) -> Result<Id> {
        let count = u16::try_from(value.len()).map_err(|e| anyhow!(e.to_string()))?;
        let service_value = ServiceValue { id, count };

        self.service_map.update(key, service_value)?;
        self.service_cache.insert(key, service_value);

        for (position, endpoint) in value.iter().enumerate() {
            let endpoint_key = EndpointKey::new(
                id,
                u16::try_from(position).map_err(|e| anyhow!(e.to_string()))?,
            );

            self.endpoint_map.update(endpoint_key, **endpoint)?;
            self.endpoint_cache.insert(endpoint_key, **endpoint);
        }
        id += 1;
        Ok(id)
    }

    fn insert_endpoints(
        &mut self,
        service_value: &ServiceValue,
        endpoints: Vec<&Self::EValue>,
    ) -> Result<()> {
        for (position, ep) in endpoints.iter().enumerate() {
            let position = u16::try_from(position)
                .map_err(|e| anyhow!("failed to convert position: {}", e))?;
            let endpoint_key = EndpointKey::new(service_value.id, position);
            self.endpoint_map.update(endpoint_key, **ep)?;
            self.endpoint_cache.insert(endpoint_key, **ep);
        }
        Ok(())
    }

    fn delete_endpoints(&mut self, service_value: &ServiceValue, range: Range<u16>) -> Result<()> {
        for idx in range {
            let endpoint_key = EndpointKey::new(service_value.id, idx);
            self.endpoint_map.delete(&endpoint_key)?;
            self.endpoint_cache.remove(&endpoint_key);
        }
        Ok(())
    }

    fn get_service_cache(&self) -> &ahash::HashMap<Self::SKey, ServiceValue> {
        &self.service_cache
    }

    fn get_service_map(&self) -> Result<ahash::HashMap<Self::SKey, ServiceValue>> {
        let mut map = HashMap::default();
        let state = self.service_map.get_state()?;

        for (k, v) in state.iter() {
            map.insert(*k, *v);
        }
        Ok(map)
    }

    fn get_endpoint_cache(&self) -> &ahash::HashMap<EndpointKey, Self::EValue> {
        &self.endpoint_cache
    }

    fn get_endpoint_map(&self) -> Result<ahash::HashMap<EndpointKey, Self::EValue>> {
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
    SE4: ServiceEndpointBpfMap,
    SE6: ServiceEndpointBpfMap,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
{
    state: Mutex<State<SE4, SE6, NP>>,
}

struct State<SE4, SE6, NP>
where
    SE4: ServiceEndpointBpfMap,
    SE6: ServiceEndpointBpfMap,
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
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
{
    shared: Arc<Shared<SE4, SE6, NP>>,
}

impl<SE4, SE6, NP> Clone for ServiceEndpointState<SE4, SE6, NP>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
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
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
{
    pub(crate) fn new(
        service_endpoint_v4: SE4,
        service_endpoint_v6: SE6,
        nodeport_map: NP,
    ) -> Self {
        let state = State {
            service_endpoint_v4,
            service_endpoint_v6,
            nodeport_cache: ahash::HashMap::default(),
            nodeport_map,
            id: 128,
        };

        let shared = Shared {
            state: Mutex::new(state),
        };
        let shared = Arc::new(shared);

        Self { shared }
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
                state
                    .service_endpoint_v4
                    .update(service_key_v4, endpoints, current_id)?
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
                state
                    .service_endpoint_v6
                    .update(service_key_v6, endpoints, current_id)?
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
                state.service_endpoint_v4.remove(service_key_v4)?;
            }
            ServiceKey::V6(service_key_v6) => {
                state.service_endpoint_v6.remove(service_key_v6)?;
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

    pub(crate) fn nodeport_state_from_map(
        &self,
    ) -> Result<ahash::HashMap<NodePortKey, ServiceKey>> {
        let state = self.shared.state.lock().unwrap();
        let map = state.nodeport_map.get_state()?;
        Ok(map
            .into_iter()
            .map(|(nodeport_key, service_key)| (nodeport_key, ServiceKey::V4(service_key)))
            .collect())
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
        let cached_service_v4 = state.service_endpoint_v4.get_service_cache();
        let cached_endpoints_v4 = state.service_endpoint_v4.get_endpoint_cache();
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
        let cached_service_v6 = state.service_endpoint_v6.get_service_cache();
        let cached_endpoints_v6 = state.service_endpoint_v6.get_endpoint_cache();
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

    // TODO: refactor with state from cache into one func
    pub(crate) fn state_from_map(&self) -> Result<ahash::HashMap<ServiceKey, Vec<EndpointValue>>> {
        let mut map = ahash::HashMap::default();
        let guard = self.shared.state.lock().unwrap();
        let service_map_v4 = guard.service_endpoint_v4.get_service_map()?;
        let endpoint_map_v4 = guard.service_endpoint_v4.get_endpoint_map()?;

        for (k, v) in service_map_v4 {
            let mut endpoints = vec![];
            let count = v.count;
            for idx in 0..count {
                let Some(endpoint_value) = endpoint_map_v4.get(&EndpointKey::new(v.id, idx)) else {
                    warn!("did not find endpoints with id {} and idx {}", v.id, idx);
                    continue;
                };
                endpoints.push(EndpointValue::V4(endpoint_value.to_owned()));
            }
            map.insert(ServiceKey::V4(k.to_owned()), endpoints);
        }

        let service_map_v6 = guard.service_endpoint_v6.get_service_map()?;
        let endpoint_map_v6 = guard.service_endpoint_v6.get_endpoint_map()?;

        for (k, v) in service_map_v6 {
            let mut endpoints = vec![];
            let count = v.count;
            for idx in 0..count {
                let Some(endpoint_value) = endpoint_map_v6.get(&EndpointKey::new(v.id, idx)) else {
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

impl<SE4, SE6, NP> ServiceBpfState for ServiceEndpointState<SE4, SE6, NP>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
{
    fn update(
        &self,
        key: ServiceKey,
        value: Vec<EndpointValue>,
    ) -> std::result::Result<(), BpfControllerError> {
        ServiceEndpointState::update(self, key, value)
            .map_err(|e| BpfControllerError::BpfState(e.to_string()))
    }

    fn remove(&self, key: &ServiceKey) -> std::result::Result<(), BpfControllerError> {
        ServiceEndpointState::remove(self, key)
            .map_err(|e| BpfControllerError::BpfState(e.to_string()))
    }

    fn state(
        &self,
    ) -> std::result::Result<ahash::HashMap<ServiceKey, Vec<EndpointValue>>, BpfControllerError>
    {
        ServiceEndpointState::state_from_map(self)
            .map_err(|e| BpfControllerError::BpfState(e.to_string()))
    }

    fn update_nodeport(
        &self,
        key: NodePortKey,
        service_key: ServiceKey,
    ) -> std::result::Result<(), BpfControllerError> {
        ServiceEndpointState::update_nodeport(self, key, service_key)
            .map_err(|e| BpfControllerError::BpfState(e.to_string()))
    }

    fn remove_nodeport(&self, key: &NodePortKey) -> std::result::Result<(), BpfControllerError> {
        ServiceEndpointState::remove_nodeport(self, key)
            .map_err(|e| BpfControllerError::BpfState(e.to_string()))
    }

    fn nodeport_state(
        &self,
    ) -> std::result::Result<ahash::HashMap<NodePortKey, ServiceKey>, BpfControllerError> {
        ServiceEndpointState::nodeport_state_from_map(self)
            .map_err(|e| BpfControllerError::BpfState(e.to_string()))
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
        ServiceEndpoint::new(service_map, endpoint_map)
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
        let service_v4 = ServiceEndpoint::new(HashMap::default(), HashMap::default());
        let service_v6 = ServiceEndpoint::new(HashMap::default(), HashMap::default());
        let nodeport = HashMap::default();
        ServiceEndpointState::new(service_v4, service_v6, nodeport)
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
        let nodeport_state = state.nodeport_state_from_map()?;

        assert!(nodeport_state.contains_key(&nodeport_key));
        Ok(())
    }
}
