use std::net::{Ipv4Addr, Ipv6Addr};

use mesh_cni_api::service::v1::{
    ListNodePortsReply, ListNodePortsRequest, ListServicesReply, ListServicesRequest,
    NodePortService, ServiceWithEndpoints,
    service_server::{Service as ServiceApi, ServiceServer},
};
use mesh_cni_ebpf_common::{
    KubeProtocol,
    service::{
        EndpointValue, EndpointValueV4, EndpointValueV6, NodePortKey, ServiceKey, ServiceKeyV4,
        ServiceKeyV6,
    },
};
use tonic::{Request, Response, Status};
use tracing::info;

use crate::bpf::{
    BpfMap,
    service::{EndpointMapStore, ServiceEndpointState, ServiceMapStore},
};

pub fn server<SE4, SE6, NP>(
    state: ServiceEndpointState<SE4, SE6, NP>,
) -> ServiceServer<Server<SE4, SE6, NP>>
where
    SE4: ServiceMapStore<SKey = ServiceKeyV4>
        + EndpointMapStore<EValue = EndpointValueV4>
        + Send
        + 'static,
    SE6: ServiceMapStore<SKey = ServiceKeyV6>
        + EndpointMapStore<EValue = EndpointValueV6>
        + Send
        + 'static,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey> + Send + 'static,
{
    info!("creating new service state");
    let server = Server::new(state);
    ServiceServer::new(server)
}

#[derive(Clone)]
pub struct Server<SE4, SE6, NP>
where
    SE4: ServiceMapStore<SKey = ServiceKeyV4> + EndpointMapStore<EValue = EndpointValueV4>,
    SE6: ServiceMapStore<SKey = ServiceKeyV6> + EndpointMapStore<EValue = EndpointValueV6>,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
{
    state: ServiceEndpointState<SE4, SE6, NP>,
}

impl<SE4, SE6, NP> Server<SE4, SE6, NP>
where
    SE4: ServiceMapStore<SKey = ServiceKeyV4> + EndpointMapStore<EValue = EndpointValueV4>,
    SE6: ServiceMapStore<SKey = ServiceKeyV6> + EndpointMapStore<EValue = EndpointValueV6>,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>,
{
    pub fn new(state: ServiceEndpointState<SE4, SE6, NP>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl<SE4, SE6, NP> ServiceApi for Server<SE4, SE6, NP>
where
    SE4: ServiceMapStore<SKey = ServiceKeyV4>
        + EndpointMapStore<EValue = EndpointValueV4>
        + Send
        + 'static,
    SE6: ServiceMapStore<SKey = ServiceKeyV6>
        + EndpointMapStore<EValue = EndpointValueV6>
        + Send
        + 'static,
    NP: BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey> + Send + 'static,
{
    async fn list_services(
        &self,
        _request: Request<ListServicesRequest>,
    ) -> std::result::Result<Response<ListServicesReply>, Status> {
        let state = self
            .state
            .state_from_cache()
            .map_err(|e| Status::new(tonic::Code::Internal, e.to_string()))?;
        let mut services = vec![];
        for (k, v) in state.iter() {
            let (service_endpoint, protocol, endpoints) = match k {
                ServiceKey::V4(service_key_v4) => {
                    let service_ip = Ipv4Addr::from_bits(service_key_v4.ip);
                    let service_port = service_key_v4.port;
                    let service_endpoint = format!("{}:{}", service_ip, service_port);
                    let protocol = KubeProtocol::try_from(service_key_v4.protocol as u32)
                        .map_err(|e| Status::new(tonic::Code::Internal, e))?
                        .to_string();
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
                ServiceKey::V6(service_key_v6) => {
                    let service_ip = Ipv6Addr::from_bits(service_key_v6.ip);
                    let service_port = service_key_v6.port;
                    let service_endpoint = format!("{}:{}", service_ip, service_port);
                    let protocol = KubeProtocol::try_from(service_key_v6.protocol as u32)
                        .map_err(|e| Status::new(tonic::Code::Internal, e))?
                        .to_string();
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
            let service = ServiceWithEndpoints {
                service_endpoint,
                protocol,
                endpoints,
            };
            services.push(service);
        }
        let response = Response::new(ListServicesReply { services });
        Ok(response)
    }

    async fn list_node_ports(
        &self,
        _request: Request<ListNodePortsRequest>,
    ) -> std::result::Result<Response<ListNodePortsReply>, Status> {
        let nodeport_state = self
            .state
            .nodeport_state_from_cache()
            .map_err(|e| Status::new(tonic::Code::Internal, e.to_string()))?;

        let mut node_ports = vec![];
        for (nodeport_key, service_key) in nodeport_state {
            let protocol = KubeProtocol::try_from(nodeport_key.protocol as u32)
                .map_err(|e| Status::new(tonic::Code::Internal, e))?
                .to_string();
            let service_endpoint = match service_key {
                ServiceKey::V4(service_key_v4) => {
                    format!(
                        "{}:{}",
                        Ipv4Addr::from_bits(service_key_v4.ip),
                        service_key_v4.port
                    )
                }
                ServiceKey::V6(service_key_v6) => {
                    format!(
                        "{}:{}",
                        Ipv6Addr::from_bits(service_key_v6.ip),
                        service_key_v6.port
                    )
                }
            };

            node_ports.push(NodePortService {
                node_port: u32::from(nodeport_key.port),
                protocol,
                service_endpoint,
            });
        }

        node_ports.sort_by(|a, b| {
            a.node_port
                .cmp(&b.node_port)
                .then(a.protocol.cmp(&b.protocol))
        });
        let response = Response::new(ListNodePortsReply { node_ports });
        Ok(response)
    }
}
