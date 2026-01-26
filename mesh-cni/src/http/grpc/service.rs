use std::net::{Ipv4Addr, Ipv6Addr};

use mesh_cni_api::service::v1::{
    ListServicesReply, ListServicesRequest, ServiceWithEndpoints,
    service_server::{Service as ServiceApi, ServiceServer},
};
use mesh_cni_ebpf_common::service::{
    EndpointValue, EndpointValueV4, EndpointValueV6, ServiceKeyV4, ServiceKeyV6,
};
use tonic::{Request, Response, Status};
use tracing::info;

use crate::bpf::service::{ServiceEndpointBpfMap, ServiceEndpointState};

pub fn server<SE4, SE6>(state: ServiceEndpointState<SE4, SE6>) -> ServiceServer<Server<SE4, SE6>>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
{
    info!("creating new service state");
    let server = Server::new(state);
    ServiceServer::new(server)
}

#[derive(Clone)]
pub struct Server<SE4, SE6>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
{
    state: ServiceEndpointState<SE4, SE6>,
}

impl<SE4, SE6> Server<SE4, SE6>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
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
    ) -> std::result::Result<Response<ListServicesReply>, Status> {
        let request = request.into_inner();
        let state = if request.from_map {
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
