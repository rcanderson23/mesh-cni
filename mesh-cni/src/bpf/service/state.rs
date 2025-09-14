use std::ops::Range;
use std::sync::{Arc, Mutex};

use ahash::HashMapExt;
use mesh_cni_common::Id;
use mesh_cni_common::service::{
    EndpointKey, EndpointValue, EndpointValueV4, EndpointValueV6, ServiceKey, ServiceKeyV4,
    ServiceKeyV6, ServiceValue,
};
use tracing::warn;

use crate::bpf::BpfMap;
use crate::{Error, Result};

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
    fn get_endpoint_cache(&self) -> &ahash::HashMap<EndpointKey, Self::EValue>;
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
    S: BpfMap<Key = SK, Value = ServiceValue>,
    E: BpfMap<Key = EndpointKey, Value = EV>,
    SK: std::hash::Hash + std::cmp::Eq + Clone + Copy,
    EV: Clone + std::cmp::PartialEq + Copy,
{
    type SKey = SK;
    type EValue = EV;
    fn update(&mut self, key: Self::SKey, value: Vec<&Self::EValue>, id: Id) -> Result<Id> {
        let new_count =
            u16::try_from(value.len()).map_err(|e| Error::ConversionError(e.to_string()))?;

        let Some(current_service_value) = self.service_cache.get(&key) else {
            return self.insert_new_service(key, value, id);
        };

        let id = current_service_value.id;
        let old_count = current_service_value.count;

        let new_service_value = ServiceValue {
            id,
            count: new_count,
        };

        self.insert_endpoints(&new_service_value, value)?;

        if old_count > new_count {
            self.delete_endpoints(&new_service_value, new_count..old_count)?;
        }

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
        let count =
            u16::try_from(value.len()).map_err(|e| Error::ConversionError(e.to_string()))?;
        let service_value = ServiceValue { id, count };

        self.service_map.update(key, service_value)?;
        self.service_cache.insert(key, service_value);

        for (position, endpoint) in value.iter().enumerate() {
            let endpoint_key = EndpointKey {
                id,
                position: u16::try_from(position)
                    .map_err(|e| Error::ConversionError(e.to_string()))?,
            };

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
            let position = u16::try_from(position).map_err(|e| {
                Error::ConversionError(format!("failed to convert position: {}", e))
            })?;
            let endpoint_key = EndpointKey {
                id: service_value.id,
                position,
            };
            self.endpoint_map.update(endpoint_key, **ep)?;
            self.endpoint_cache.insert(endpoint_key, **ep);
        }
        Ok(())
    }

    fn delete_endpoints(&mut self, service_value: &ServiceValue, range: Range<u16>) -> Result<()> {
        for idx in range {
            let endpoint_key = EndpointKey {
                id: service_value.id,
                position: idx,
            };
            self.endpoint_map.delete(&endpoint_key)?;
            self.endpoint_cache.remove(&endpoint_key);
        }
        Ok(())
    }

    fn get_service_cache(&self) -> &ahash::HashMap<Self::SKey, ServiceValue> {
        &self.service_cache
    }

    fn get_endpoint_cache(&self) -> &ahash::HashMap<EndpointKey, Self::EValue> {
        &self.endpoint_cache
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
                let Some(endpoint_value) = cached_endpoints_v4.get(&EndpointKey {
                    id: v.id,
                    position: idx,
                }) else {
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
                let Some(endpoint_value) = cached_endpoints_v6.get(&EndpointKey {
                    id: v.id,
                    position: idx,
                }) else {
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

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use ahash::HashMap;
    use mesh_cni_common::KubeProtocol;

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

        let service_key = ServiceKeyV4 {
            ip: Ipv4Addr::new(192, 168, 0, 1).to_bits(),
            port: 80,
            protocol: KubeProtocol::Tcp,
        };
        let endpoint_one = EndpointValueV4 {
            ip: Ipv4Addr::new(10, 0, 0, 1).to_bits(),
            port: 8080,
            _protocol: mesh_cni_common::KubeProtocol::Tcp,
        };
        let endpoint_two = EndpointValueV4 {
            ip: Ipv4Addr::new(10, 0, 0, 2).to_bits(),
            port: 8080,
            _protocol: mesh_cni_common::KubeProtocol::Tcp,
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
}
