use std::{
    ops::Range,
    sync::{Arc, Mutex},
};

use ahash::{HashMap, HashMapExt};
use anyhow::anyhow;
use mesh_cni_ebpf_common::{
    Id,
    service::{
        EndpointKey, EndpointValue, EndpointValueV4, EndpointValueV6, NodePortFrontendValue,
        NodePortKey, ServiceKey, ServiceKeyV4, ServiceKeyV6, ServiceValue,
    },
};
use mesh_cni_service_bpf_controller::{
    Error as BpfControllerError, NodePortMapKey, ServiceBpfState,
};
use tracing::warn;

use crate::{Result, bpf::BpfMap};

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

struct NodePortShared<N4, N6, P4, P6>
where
    N4: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
    N6: BpfMap<Key = NodePortKey, Value = ServiceKeyV6, KeyOutput = NodePortKey>,
    P4: BpfMap<Key = NodePortKey, Value = NodePortFrontendValue, KeyOutput = NodePortKey>,
    P6: BpfMap<Key = NodePortKey, Value = NodePortFrontendValue, KeyOutput = NodePortKey>,
{
    state: Mutex<NodePortStateInner<N4, N6, P4, P6>>,
}

struct NodePortStateInner<N4, N6, P4, P6>
where
    N4: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
    N6: BpfMap<Key = NodePortKey, Value = ServiceKeyV6, KeyOutput = NodePortKey>,
    P4: BpfMap<Key = NodePortKey, Value = NodePortFrontendValue, KeyOutput = NodePortKey>,
    P6: BpfMap<Key = NodePortKey, Value = NodePortFrontendValue, KeyOutput = NodePortKey>,
{
    frontend_map_v4: N4,
    frontend_map_v6: N6,
    policy_map_v4: P4,
    policy_map_v6: P6,
    frontend_cache_v4: ahash::HashMap<NodePortKey, ServiceKeyV4>,
    frontend_cache_v6: ahash::HashMap<NodePortKey, ServiceKeyV6>,
    policy_cache_v4: ahash::HashMap<NodePortKey, NodePortFrontendValue>,
    policy_cache_v6: ahash::HashMap<NodePortKey, NodePortFrontendValue>,
}

#[derive(Clone)]
pub struct NodePortState<N4, N6, P4, P6>
where
    N4: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
    N6: BpfMap<Key = NodePortKey, Value = ServiceKeyV6, KeyOutput = NodePortKey>,
    P4: BpfMap<Key = NodePortKey, Value = NodePortFrontendValue, KeyOutput = NodePortKey>,
    P6: BpfMap<Key = NodePortKey, Value = NodePortFrontendValue, KeyOutput = NodePortKey>,
{
    shared: Arc<NodePortShared<N4, N6, P4, P6>>,
}

impl<N4, N6, P4, P6> NodePortState<N4, N6, P4, P6>
where
    N4: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
    N6: BpfMap<Key = NodePortKey, Value = ServiceKeyV6, KeyOutput = NodePortKey>,
    P4: BpfMap<Key = NodePortKey, Value = NodePortFrontendValue, KeyOutput = NodePortKey>,
    P6: BpfMap<Key = NodePortKey, Value = NodePortFrontendValue, KeyOutput = NodePortKey>,
{
    pub fn new(
        frontend_map_v4: N4,
        frontend_map_v6: N6,
        policy_map_v4: P4,
        policy_map_v6: P6,
    ) -> Self {
        let shared = NodePortShared {
            state: Mutex::new(NodePortStateInner {
                frontend_map_v4,
                frontend_map_v6,
                policy_map_v4,
                policy_map_v6,
                frontend_cache_v4: HashMap::default(),
                frontend_cache_v6: HashMap::default(),
                policy_cache_v4: HashMap::default(),
                policy_cache_v6: HashMap::default(),
            }),
        };
        Self {
            shared: Arc::new(shared),
        }
    }

    fn update_frontend(&self, key: NodePortMapKey, value: ServiceKey) -> Result<()> {
        let mut state = self.shared.state.lock().unwrap();
        match (key, value) {
            (NodePortMapKey::V4(frontend), ServiceKey::V4(service_key)) => {
                state.frontend_map_v4.update(frontend, service_key)?;
                state.frontend_cache_v4.insert(frontend, service_key);
                Ok(())
            }
            (NodePortMapKey::V6(frontend), ServiceKey::V6(service_key)) => {
                state.frontend_map_v6.update(frontend, service_key)?;
                state.frontend_cache_v6.insert(frontend, service_key);
                Ok(())
            }
            _ => Err(anyhow!("nodeport frontend key/value family mismatch")),
        }
    }

    fn remove_frontend(&self, key: &NodePortMapKey) -> Result<()> {
        let mut state = self.shared.state.lock().unwrap();
        match key {
            NodePortMapKey::V4(frontend) => {
                state.frontend_map_v4.delete(frontend)?;
                state.frontend_cache_v4.remove(frontend);
            }
            NodePortMapKey::V6(frontend) => {
                state.frontend_map_v6.delete(frontend)?;
                state.frontend_cache_v6.remove(frontend);
            }
        }
        Ok(())
    }

    fn update_policy(&self, key: NodePortMapKey, value: NodePortFrontendValue) -> Result<()> {
        let mut state = self.shared.state.lock().unwrap();
        match key {
            NodePortMapKey::V4(frontend) => {
                state.policy_map_v4.update(frontend, value)?;
                state.policy_cache_v4.insert(frontend, value);
            }
            NodePortMapKey::V6(frontend) => {
                state.policy_map_v6.update(frontend, value)?;
                state.policy_cache_v6.insert(frontend, value);
            }
        }
        Ok(())
    }

    fn remove_policy(&self, key: &NodePortMapKey) -> Result<()> {
        let mut state = self.shared.state.lock().unwrap();
        match key {
            NodePortMapKey::V4(frontend) => {
                state.policy_map_v4.delete(frontend)?;
                state.policy_cache_v4.remove(frontend);
            }
            NodePortMapKey::V6(frontend) => {
                state.policy_map_v6.delete(frontend)?;
                state.policy_cache_v6.remove(frontend);
            }
        }
        Ok(())
    }

    fn frontend_state_from_map(&self) -> Result<ahash::HashMap<NodePortMapKey, ServiceKey>> {
        let state = self.shared.state.lock().unwrap();
        let mut map = HashMap::default();

        for (key, value) in state.frontend_map_v4.get_state()? {
            map.insert(NodePortMapKey::V4(key), ServiceKey::V4(value));
        }
        for (key, value) in state.frontend_map_v6.get_state()? {
            map.insert(NodePortMapKey::V6(key), ServiceKey::V6(value));
        }

        Ok(map)
    }
}

#[derive(Clone)]
pub struct ControllerServiceBpfState<SE4, SE6, N4, N6, P4, P6>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
    N4: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
    N6: BpfMap<Key = NodePortKey, Value = ServiceKeyV6, KeyOutput = NodePortKey>,
    P4: BpfMap<Key = NodePortKey, Value = NodePortFrontendValue, KeyOutput = NodePortKey>,
    P6: BpfMap<Key = NodePortKey, Value = NodePortFrontendValue, KeyOutput = NodePortKey>,
{
    pub service_endpoint_state: ServiceEndpointState<SE4, SE6>,
    pub nodeport_state: NodePortState<N4, N6, P4, P6>,
}

impl<SE4, SE6, N4, N6, P4, P6> ControllerServiceBpfState<SE4, SE6, N4, N6, P4, P6>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
    N4: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
    N6: BpfMap<Key = NodePortKey, Value = ServiceKeyV6, KeyOutput = NodePortKey>,
    P4: BpfMap<Key = NodePortKey, Value = NodePortFrontendValue, KeyOutput = NodePortKey>,
    P6: BpfMap<Key = NodePortKey, Value = NodePortFrontendValue, KeyOutput = NodePortKey>,
{
    pub fn new(
        service_endpoint_state: ServiceEndpointState<SE4, SE6>,
        nodeport_state: NodePortState<N4, N6, P4, P6>,
    ) -> Self {
        Self {
            service_endpoint_state,
            nodeport_state,
        }
    }
}

struct Shared<SE4, SE6>
where
    SE4: ServiceEndpointBpfMap,
    SE6: ServiceEndpointBpfMap,
{
    state: Mutex<State<SE4, SE6>>,
}

struct State<SE4, SE6>
where
    SE4: ServiceEndpointBpfMap,
    SE6: ServiceEndpointBpfMap,
{
    service_endpoint_v4: SE4,
    service_endpoint_v6: SE6,
    id: Id,
}

pub struct ServiceEndpointState<SE4, SE6>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
{
    shared: Arc<Shared<SE4, SE6>>,
}

impl<SE4, SE6> Clone for ServiceEndpointState<SE4, SE6>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
{
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<SE4, SE6> ServiceEndpointState<SE4, SE6>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
{
    pub(crate) fn new(service_endpoint_v4: SE4, service_endpoint_v6: SE6) -> Self {
        let state = State {
            service_endpoint_v4,
            service_endpoint_v6,
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

impl<SE4, SE6> ServiceBpfState for ServiceEndpointState<SE4, SE6>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
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
        _key: NodePortMapKey,
        _value: ServiceKey,
    ) -> std::result::Result<(), BpfControllerError> {
        Err(BpfControllerError::Other(
            "nodeport frontend updates are not supported on ServiceEndpointState".into(),
        ))
    }

    fn remove_nodeport(
        &self,
        _key: &NodePortMapKey,
    ) -> std::result::Result<(), BpfControllerError> {
        Err(BpfControllerError::Other(
            "nodeport frontend removes are not supported on ServiceEndpointState".into(),
        ))
    }

    fn update_nodeport_policy(
        &self,
        _key: NodePortMapKey,
        _value: NodePortFrontendValue,
    ) -> std::result::Result<(), BpfControllerError> {
        Err(BpfControllerError::Other(
            "nodeport policy updates are not supported on ServiceEndpointState".into(),
        ))
    }

    fn remove_nodeport_policy(
        &self,
        _key: &NodePortMapKey,
    ) -> std::result::Result<(), BpfControllerError> {
        Err(BpfControllerError::Other(
            "nodeport policy removes are not supported on ServiceEndpointState".into(),
        ))
    }

    fn nodeport_state(
        &self,
    ) -> std::result::Result<ahash::HashMap<NodePortMapKey, ServiceKey>, BpfControllerError> {
        Ok(HashMap::default())
    }
}

impl<SE4, SE6, N4, N6, P4, P6> ServiceBpfState
    for ControllerServiceBpfState<SE4, SE6, N4, N6, P4, P6>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
    N4: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
    N6: BpfMap<Key = NodePortKey, Value = ServiceKeyV6, KeyOutput = NodePortKey>,
    P4: BpfMap<Key = NodePortKey, Value = NodePortFrontendValue, KeyOutput = NodePortKey>,
    P6: BpfMap<Key = NodePortKey, Value = NodePortFrontendValue, KeyOutput = NodePortKey>,
{
    fn update(
        &self,
        key: ServiceKey,
        value: Vec<EndpointValue>,
    ) -> std::result::Result<(), BpfControllerError> {
        self.service_endpoint_state
            .update(key, value)
            .map_err(|e| BpfControllerError::BpfState(e.to_string()))
    }

    fn remove(&self, key: &ServiceKey) -> std::result::Result<(), BpfControllerError> {
        self.service_endpoint_state
            .remove(key)
            .map_err(|e| BpfControllerError::BpfState(e.to_string()))
    }

    fn state(
        &self,
    ) -> std::result::Result<ahash::HashMap<ServiceKey, Vec<EndpointValue>>, BpfControllerError>
    {
        self.service_endpoint_state
            .state_from_map()
            .map_err(|e| BpfControllerError::BpfState(e.to_string()))
    }

    fn update_nodeport(
        &self,
        key: NodePortMapKey,
        value: ServiceKey,
    ) -> std::result::Result<(), BpfControllerError> {
        self.nodeport_state
            .update_frontend(key, value)
            .map_err(|e| BpfControllerError::BpfState(e.to_string()))
    }

    fn remove_nodeport(&self, key: &NodePortMapKey) -> std::result::Result<(), BpfControllerError> {
        self.nodeport_state
            .remove_frontend(key)
            .map_err(|e| BpfControllerError::BpfState(e.to_string()))
    }

    fn update_nodeport_policy(
        &self,
        key: NodePortMapKey,
        value: NodePortFrontendValue,
    ) -> std::result::Result<(), BpfControllerError> {
        self.nodeport_state
            .update_policy(key, value)
            .map_err(|e| BpfControllerError::BpfState(e.to_string()))
    }

    fn remove_nodeport_policy(
        &self,
        key: &NodePortMapKey,
    ) -> std::result::Result<(), BpfControllerError> {
        self.nodeport_state
            .remove_policy(key)
            .map_err(|e| BpfControllerError::BpfState(e.to_string()))
    }

    fn nodeport_state(
        &self,
    ) -> std::result::Result<ahash::HashMap<NodePortMapKey, ServiceKey>, BpfControllerError> {
        self.nodeport_state
            .frontend_state_from_map()
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
}
