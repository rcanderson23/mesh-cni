use std::net::{Ipv4Addr, Ipv6Addr};

use mesh_cni_api::service::v1::service_server::Service as ServiceApi;
use mesh_cni_api::service::v1::{ListServicesReply, ListServicesRequest, ServiceWithEndpoints};
use mesh_cni_ebpf_common::service::{
    EndpointValue, EndpointValueV4, EndpointValueV6, ServiceKeyV4, ServiceKeyV6,
};
use tonic::{Request, Response, Status};
use tracing::{error, info};

use crate::bpf::service::state::{ServiceEndpointBpfMap, ServiceEndpointState};
use crate::bpf::service::{load_endpoint_maps, load_service_maps};

#[derive(Clone)]
pub struct Server<SE4, SE6>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4> + Send + 'static,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6> + Send + 'static,
{
    state: ServiceEndpointState<SE4, SE6>,
}

impl<SE4, SE6> Server<SE4, SE6>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4> + Send + 'static,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6> + Send + 'static,
{
    pub fn new(state: ServiceEndpointState<SE4, SE6>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl<SE4, SE6> ServiceApi for Server<SE4, SE6>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4> + Send + 'static,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6> + Send + 'static,
{
    async fn list_services(
        &self,
        request: Request<ListServicesRequest>,
    ) -> Result<Response<ListServicesReply>, Status> {
        let request = request.into_inner();
        let state = if request.from_map {
            let (service_ipv4, _) = load_service_maps().unwrap();
            let (endpoint_ipv4, _) = load_endpoint_maps().unwrap();
            info!("dumping map");
            for kv in service_ipv4.iter() {
                match kv {
                    Ok((k, v)) => info!(
                        "IP:{} Port: {} ID: {} Count: {} ",
                        Ipv4Addr::from_bits(k.ip),
                        k.port,
                        v.id,
                        v.count
                    ),
                    Err(e) => error!("{e}"),
                }
            }
            for kv in endpoint_ipv4.iter() {
                match kv {
                    Ok((k, v)) => info!(
                        "IP: {} Port: {} Position: {} ID: {}",
                        Ipv4Addr::from_bits(v.ip),
                        v.port,
                        k.position,
                        k.id
                    ),
                    Err(e) => error!("{e}"),
                }
            }
            info!("finished dumping map");
            self.state
                .state_from_map()
                .map_err(|e| Status::new(tonic::Code::Internal, e.to_string()))?
        } else {
            self.state
                .state_from_cache()
                .map_err(|e| Status::new(tonic::Code::Internal, e.to_string()))?
        };
        let mut services = vec![];
        for (k, v) in state.iter() {
            let (service_endpoint, protocol, endpoints) = match k {
                mesh_cni_ebpf_common::service::ServiceKey::V4(service_key_v4) => {
                    let service_ip = Ipv4Addr::from_bits(service_key_v4.ip);
                    let service_port = service_key_v4.port;
                    let service_endpoint = format!("{}:{}", service_ip, service_port);
                    let protocol = service_key_v4.protocol.to_string();
                    let endpoints = v
                        .iter()
                        .filter_map(|e| {
                            if let EndpointValue::V4(e) = e {
                                Some(format!("{}:{}", Ipv4Addr::from_bits(e.ip), e.port))
                            } else {
                                None
                            }
                        })
                        .collect();

                    (service_endpoint, protocol, endpoints)
                }
                mesh_cni_ebpf_common::service::ServiceKey::V6(service_key_v6) => {
                    let service_ip = Ipv6Addr::from_bits(service_key_v6.ip);
                    let service_port = service_key_v6.port;
                    let service_endpoint = format!("{}:{}", service_ip, service_port);
                    let protocol = service_key_v6.protocol.to_string();
                    let endpoints = v
                        .iter()
                        .filter_map(|e| {
                            if let EndpointValue::V6(e) = e {
                                Some(format!("{}:{}", Ipv6Addr::from_bits(e.ip), e.port))
                            } else {
                                None
                            }
                        })
                        .collect();

                    (service_endpoint, protocol, endpoints)
                }
            };
            let s = ServiceWithEndpoints {
                service_endpoint,
                protocol,
                endpoints,
            };
            services.push(s);
        }
        let response = Response::new(ListServicesReply { services });
        Ok(response)
    }
}
