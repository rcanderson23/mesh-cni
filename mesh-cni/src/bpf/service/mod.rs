mod api;
pub use api::Server as BpfServiceServer;

mod state;
pub use state::ServiceEndpointBpfMap;
pub use state::ServiceEndpointState as BpfServiceEndpointState;

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;

use kube::{Api, Client};
use mesh_cni_api::service::v1::service_server::ServiceServer;
use mesh_cni_ebpf_common::service::{
    EndpointKey, EndpointValueV4, EndpointValueV6, ServiceKeyV4, ServiceKeyV6, ServiceValue,
};
use tokio_util::sync::CancellationToken;

use crate::Result;
use crate::bpf::BpfMap;
use crate::bpf::service::api::Server;
use crate::bpf::service::state::ServiceEndpoint;
use crate::kubernetes::controllers::bpf_service::start_bpf_meshendpoint_controller;
use crate::kubernetes::controllers::bpf_service::start_bpf_service_controller;
use crate::kubernetes::{ClusterId, create_store_and_subscriber};

pub async fn run<S4, S6, E4, E6>(
    service_map_v4: S4,
    service_map_v6: S6,
    endpoint_map_v4: E4,
    endpoint_map_v6: E6,
    kube_client: Client,
    _cluster_id: ClusterId,
    cancel: CancellationToken,
) -> Result<
    ServiceServer<
        Server<
            ServiceEndpoint<S4, E4, ServiceKeyV4, EndpointValueV4>,
            ServiceEndpoint<S6, E6, ServiceKeyV6, EndpointValueV6>,
        >,
    >,
>
where
    S4: BpfMap<Key = ServiceKeyV4, Value = ServiceValue, KeyOutput = ServiceKeyV4> + Send + 'static,
    S6: BpfMap<Key = ServiceKeyV6, Value = ServiceValue, KeyOutput = ServiceKeyV6> + Send + 'static,
    E4: BpfMap<Key = EndpointKey, Value = EndpointValueV4, KeyOutput = EndpointKey>
        + Send
        + 'static,
    E6: BpfMap<Key = EndpointKey, Value = EndpointValueV6, KeyOutput = EndpointKey>
        + Send
        + 'static,
{
    let service_endpoint_v4 = ServiceEndpoint::new(service_map_v4, endpoint_map_v4);
    let service_endpoint_v6 = ServiceEndpoint::new(service_map_v6, endpoint_map_v6);
    let state = state::ServiceEndpointState::new(service_endpoint_v4, service_endpoint_v6);
    let server = Server::new(state.clone());
    let server = mesh_cni_api::service::v1::service_server::ServiceServer::new(server);

    let service_api: Api<Service> = Api::all(kube_client.clone());
    let (service_state, service_subscriber) =
        create_store_and_subscriber(service_api.clone()).await?;

    let endpoint_slice_api: Api<EndpointSlice> = Api::all(kube_client.clone());
    let (endpoint_slice_state, endpoint_slice_subscriber) =
        create_store_and_subscriber(endpoint_slice_api.clone()).await?;

    let mesh_endpoint_api = Api::all(kube_client.clone());
    let (mesh_endpoint_state, _) = create_store_and_subscriber(mesh_endpoint_api.clone()).await?;

    let service_controller = start_bpf_service_controller(
        service_state.clone(),
        service_subscriber,
        endpoint_slice_state.clone(),
        endpoint_slice_subscriber,
        mesh_endpoint_state.clone(),
        state.clone(),
        cancel.clone(),
    );

    let mesh_endpoint_controller = start_bpf_meshendpoint_controller(
        mesh_endpoint_api,
        service_state,
        endpoint_slice_state,
        mesh_endpoint_state,
        state,
        cancel.clone(),
    );
    tokio::spawn(service_controller);
    tokio::spawn(mesh_endpoint_controller);

    Ok(server)
}
