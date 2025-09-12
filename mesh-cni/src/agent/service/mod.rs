use kube::Client;
use mesh_cni_api::service::v1::service_server::ServiceServer;
use mesh_cni_common::service::{EndpointKeyV4, EndpointValueV4, ServiceKeyV4, ServiceValue};
use tokio::task::JoinHandle;

use crate::Result;
use crate::agent::BpfMap;
use crate::agent::service::server::Server;
use crate::kubernetes::ClusterId;
use crate::kubernetes::service::ServiceEndpointState;

mod server;
pub mod state;

pub async fn run<S, E>(
    service_map: S,
    endpoint_map: E,
    kube_client: Client,
    cluster_id: ClusterId,
) -> Result<(ServiceServer<Server<S, E>>, JoinHandle<Result<()>>)>
where
    S: BpfMap<ServiceKeyV4, ServiceValue> + Send + 'static,
    E: BpfMap<EndpointKeyV4, EndpointValueV4> + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(1000);
    let svc_epslice_state = ServiceEndpointState::try_new(kube_client, cluster_id, tx).await?;
    let state = state::State::new(service_map, endpoint_map);
    let server = Server::new(state, rx).await;
    let server = mesh_cni_api::service::v1::service_server::ServiceServer::new(server);

    let h = tokio::spawn(async move { svc_epslice_state.start().await });
    Ok((server, h))
}
