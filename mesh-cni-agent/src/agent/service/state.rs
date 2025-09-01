use std::ops::Range;

use ahash::HashMapExt;
use mesh_cni_common::Id;
use mesh_cni_common::service_v4::{EndpointKeyV4, EndpointValueV4, ServiceKeyV4, ServiceValueV4};
use tracing::warn;

use crate::agent::{BpfMap, BpfState};
use crate::{Error, Result};

pub type ServiceState<S> = BpfState<S, ServiceKeyV4, ServiceValueV4>;
pub type EndpointState<E> = BpfState<E, EndpointKeyV4, EndpointValueV4>;

pub struct State<S, E>
where
    S: BpfMap<ServiceKeyV4, ServiceValueV4>,
    E: BpfMap<EndpointKeyV4, EndpointValueV4>,
{
    service_map: ServiceState<S>,
    endpoint_map: EndpointState<E>,
    id: Id,
}

impl<S, E> State<S, E>
where
    S: BpfMap<ServiceKeyV4, ServiceValueV4>,
    E: BpfMap<EndpointKeyV4, EndpointValueV4>,
{
    pub(crate) fn new(service_map: S, endpoint_map: E) -> Self {
        Self {
            service_map: BpfState::new(service_map),
            endpoint_map: BpfState::new(endpoint_map),
            id: 128,
        }
    }

    pub(crate) fn update(&mut self, key: ServiceKeyV4, value: Vec<ServiceKeyV4>) -> Result<()> {
        let new_count =
            u16::try_from(value.len()).map_err(|e| Error::ConversionError(e.to_string()))?;

        let Some(service_value) = self.service_map.get_from_cache(&key) else {
            return self.insert_new_service(key, value);
        };
        let service_value = *service_value;

        let old_count = service_value.count;

        self.insert_endpoints(&service_value, value)?;

        if old_count > new_count {
            return self.delete_endpoints(&service_value, new_count..old_count);
        }

        Ok(())
    }

    pub(crate) fn remove(&mut self, key: &ServiceKeyV4) -> Result<()> {
        let Some(service_value) = self.service_map.get_from_cache(key) else {
            return Ok(());
        };
        let service_value = *service_value;

        let range = 0..service_value.count;
        self.delete_endpoints(&service_value, range)?;

        self.service_map.delete(key)?;
        Ok(())
    }

    pub(crate) fn state_from_cache(
        &self,
    ) -> Result<ahash::HashMap<ServiceKeyV4, Vec<EndpointValueV4>>> {
        let mut map = ahash::HashMap::new();
        for (k, v) in self.service_map.cache.iter() {
            let mut endpoints = vec![];
            let count = v.count;
            for idx in 0..count {
                let Some(ep) = self.endpoint_map.cache.get(&EndpointKeyV4 {
                    id: v.id,
                    position: idx,
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

    fn insert_new_service(&mut self, key: ServiceKeyV4, value: Vec<ServiceKeyV4>) -> Result<()> {
        let count =
            u16::try_from(value.len()).map_err(|e| Error::ConversionError(e.to_string()))?;
        let service_value = ServiceValueV4 { id: self.id, count };

        self.service_map.update(key, service_value)?;

        for (position, key) in value.iter().enumerate() {
            let endpoint_key = EndpointKeyV4 {
                id: self.id,
                position: u16::try_from(position)
                    .map_err(|e| Error::ConversionError(e.to_string()))?,
            };
            let endpoint_value = EndpointValueV4 {
                ip: key.ip,
                port: key.port,
                _protocol: key.protocol,
            };

            self.endpoint_map.update(endpoint_key, endpoint_value)?
        }
        self.id += 1;
        Ok(())
    }

    fn insert_endpoints(
        &mut self,
        service_value: &ServiceValueV4,
        endpoints: Vec<ServiceKeyV4>,
    ) -> Result<()> {
        for (position, ep) in endpoints.iter().enumerate() {
            let position = u16::try_from(position).map_err(|e| {
                Error::ConversionError(format!("failed to convert position: {}", e))
            })?;
            let endpoint_key = EndpointKeyV4 {
                id: service_value.id,
                position,
            };
            let endpoint_value = EndpointValueV4 {
                ip: ep.ip,
                port: ep.port,
                _protocol: ep.protocol,
            };

            self.endpoint_map.update(endpoint_key, endpoint_value)?;
        }
        Ok(())
    }

    fn delete_endpoints(
        &mut self,
        service_value: &ServiceValueV4,
        range: Range<u16>,
    ) -> Result<()> {
        for idx in range {
            let endpoint_key = EndpointKeyV4 {
                id: service_value.id,
                position: idx,
            };
            self.endpoint_map.delete(&endpoint_key)?;
        }
        Ok(())
    }
}
