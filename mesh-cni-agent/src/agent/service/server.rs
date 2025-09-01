use std::net::IpAddr;
use std::sync::Arc;

use mesh_cni_api::service::v1::service_server::Service as ServiceApi;
use mesh_cni_api::service::v1::{ListServicesReply, ListServicesRequest, ServiceWithEndpoints};
use mesh_cni_common::service_v4::{EndpointKeyV4, EndpointValueV4, ServiceKeyV4, ServiceValueV4};
use tokio::sync::Mutex;
use tokio::sync::mpsc::Receiver;
use tonic::{Request, Response, Status};
use tracing::{error, info};

use crate::agent::BpfMap;
use crate::agent::service::state::State;
use crate::kubernetes::service::EndpointEvent;

#[derive(Clone)]
pub struct Server<S, E>
where
    S: BpfMap<ServiceKeyV4, ServiceValueV4>,
    E: BpfMap<EndpointKeyV4, EndpointValueV4>,
{
    state: Arc<Mutex<State<S, E>>>,
}

impl<S, E> Server<S, E>
where
    S: BpfMap<ServiceKeyV4, ServiceValueV4> + Send + 'static,
    E: BpfMap<EndpointKeyV4, EndpointValueV4> + Send + 'static,
{
    pub async fn new(state: State<S, E>, rx: Receiver<EndpointEvent>) -> Self {
        let state = Arc::new(Mutex::new(state));
        let event_state = state.clone();

        tokio::spawn(start_event_receiver(event_state, rx));
        Self { state }
    }
}

#[tonic::async_trait]
impl<S, E> ServiceApi for Server<S, E>
where
    S: BpfMap<ServiceKeyV4, ServiceValueV4> + Send + 'static,
    E: BpfMap<EndpointKeyV4, EndpointValueV4> + Send + 'static,
{
    async fn list_services(
        &self,
        _request: Request<ListServicesRequest>,
    ) -> Result<Response<ListServicesReply>, Status> {
        let state = self.state.lock().await;
        let cached_state = state
            .state_from_cache()
            .map_err(|e| Status::new(tonic::Code::Internal, e.to_string()))?;
        drop(state);
        let mut services = vec![];
        for (k, v) in cached_state.iter() {
            let endpoints = v
                .iter()
                .map(|e| {
                    let service_ip: IpAddr = IpAddr::V4(e.ip.into());
                    format!("{}:{}", service_ip, e.port)
                })
                .collect();
            let backend_ip: IpAddr = IpAddr::V4(k.ip.into());
            let s = ServiceWithEndpoints {
                service_endpoint: format!("{}:{}", backend_ip, k.port),
                protocol: k.protocol.to_string(),
                endpoints,
            };
            services.push(s);
        }
        let response = Response::new(ListServicesReply { services });
        Ok(response)
    }
}

async fn start_event_receiver<S, E>(state: Arc<Mutex<State<S, E>>>, mut rx: Receiver<EndpointEvent>)
where
    S: BpfMap<ServiceKeyV4, ServiceValueV4> + Send + 'static,
    E: BpfMap<EndpointKeyV4, EndpointValueV4> + Send + 'static,
{
    while let Some(ev) = rx.recv().await {
        let mut state = state.lock().await;
        match ev {
            EndpointEvent::Update(service_identity) => {
                let service = service_identity.service_destination;
                let destinations = service_identity.ready_destinations;

                info!(
                    "updating service map with service {}:{}/{}",
                    service.ip, service.port, service.protocol
                );
                if let Err(e) = state.update(service, destinations) {
                    error!(%e, "failed to update map");
                    continue;
                }
            }
            EndpointEvent::Delete(service) => {
                info!(
                    "deleting service map entry {}:{}/{}",
                    service.ip, service.port, service.protocol
                );
                if let Err(e) = state.remove(&service) {
                    error!(%e, "failed to update map");
                    continue;
                }
            }
        }
    }
}
