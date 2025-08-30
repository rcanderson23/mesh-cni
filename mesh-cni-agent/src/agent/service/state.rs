use std::ops::RangeInclusive;

use ahash::HashMapExt;
use mesh_cni_common::{EndpointKey, EndpointValue, Id, ServiceKey, ServiceValue};
use tracing::warn;

use crate::agent::{BpfMap, BpfState};
use crate::{Error, Result};

pub type ServiceState<S: BpfMap<ServiceKey, ServiceValue>> = BpfState<S, ServiceKey, ServiceValue>;
pub type EndpointState<E: BpfMap<EndpointKey, EndpointValue>> =
    BpfState<E, EndpointKey, EndpointValue>;

pub struct State<S, E>
where
    S: BpfMap<ServiceKey, ServiceValue>,
    E: BpfMap<EndpointKey, EndpointValue>,
{
    service_map: ServiceState<S>,
    endpoint_map: EndpointState<E>,
    id: Id,
}

impl<S, E> State<S, E>
where
    S: BpfMap<ServiceKey, ServiceValue>,
    E: BpfMap<EndpointKey, EndpointValue>,
{
    pub(crate) fn new(service_map: S, endpoint_map: E) -> Self {
        Self {
            service_map: BpfState::new(service_map),
            endpoint_map: BpfState::new(endpoint_map),
            id: 128,
        }
    }

    pub(crate) fn update(&mut self, key: ServiceKey, value: Vec<ServiceKey>) -> Result<()> {
        let new_count =
            u16::try_from(value.len()).map_err(|e| Error::ConversionError(e.to_string()))?;

        let Some(service_value) = self.service_map.get_from_cache(&key) else {
            return self.insert_new_service(key, value);
        };
        let service_value = service_value.clone();

        let old_count = service_value.count;

        self.insert_endpoints(&service_value, value)?;

        if old_count > new_count {
            self.delete_endpoints(&service_value, (new_count + 1)..=old_count);
        }

        Ok(())
    }

    pub(crate) fn remove(&mut self, key: &ServiceKey) -> Result<()> {
        let Some(service_value) = self.service_map.get_from_cache(&key) else {
            return Ok(());
        };
        let service_value = service_value.clone();

        let range = 1..=service_value.count;
        self.delete_endpoints(&service_value, range)?;

        self.service_map.delete(key)?;
        Ok(())
    }

    pub(crate) fn state_from_cache(
        &self,
    ) -> Result<ahash::HashMap<ServiceKey, Vec<EndpointValue>>> {
        let mut map = ahash::HashMap::new();
        for (k, v) in self.service_map.cache.iter() {
            let mut endpoints = vec![];
            let count = v.count;
            for idx in 1..=count {
                let Some(ep) = self.endpoint_map.cache.get(&EndpointKey {
                    id: v.id,
                    position: idx as u16,
                }) else {
                    warn!("did not find endpoints with id {} and idx {}", v.id, idx);
                    continue;
                };
                endpoints.push(ep.to_owned());
            }
            map.insert(k.to_owned(), endpoints);
        }
        Ok(map)
    }

    fn insert_new_service(&mut self, key: ServiceKey, value: Vec<ServiceKey>) -> Result<()> {
        let count =
            u16::try_from(value.len()).map_err(|e| Error::ConversionError(e.to_string()))?;
        let service_value = ServiceValue { id: self.id, count };

        if let Err(e) = self.service_map.update(key, service_value) {
            return Err(e);
        }

        let mut position = 0;
        for val in value {
            position += 1;
            let endpoint_key = EndpointKey {
                id: self.id,
                position,
            };
            let endpoint_value = EndpointValue {
                ip: val.ip,
                port: val.port,
                _protocol: val.protocol,
            };

            if let Err(e) = self.endpoint_map.update(endpoint_key, endpoint_value) {
                return Err(e);
            }
        }
        self.id += 1;
        Ok(())
    }

    fn insert_endpoints(
        &mut self,
        service_value: &ServiceValue,
        endpoints: Vec<ServiceKey>,
    ) -> Result<()> {
        let mut position = 0;
        for ep in endpoints {
            position += 1;
            let endpoint_key = EndpointKey {
                id: service_value.id,
                position,
            };
            let endpoint_value = EndpointValue {
                ip: ep.ip,
                port: ep.port,
                _protocol: ep.protocol,
            };

            if let Err(e) = self.endpoint_map.update(endpoint_key, endpoint_value) {
                return Err(e);
            }
        }
        Ok(())
    }

    fn delete_endpoints(
        &mut self,
        service_value: &ServiceValue,
        range: RangeInclusive<u16>,
    ) -> Result<()> {
        for idx in range {
            let endpoint_key = EndpointKey {
                id: service_value.id,
                position: idx,
            };
            self.endpoint_map.delete(&endpoint_key)?;
        }
        Ok(())
    }
}
