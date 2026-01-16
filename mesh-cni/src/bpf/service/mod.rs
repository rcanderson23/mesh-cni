mod api;
pub use api::Server as BpfServiceServer;

mod state;
use std::time::Duration;

use aya::maps::{HashMap, Map, MapData};
use k8s_openapi::api::{core::v1::Service, discovery::v1::EndpointSlice};
use kube::{Api, Client};
use mesh_cni_api::service::v1::service_server::ServiceServer;
use mesh_cni_ebpf_common::service::{
    EndpointKey, EndpointValueV4, EndpointValueV6, ServiceKeyV4, ServiceKeyV6, ServiceValue,
};
use mesh_cni_k8s_utils::create_store_and_subscriber;
use mesh_cni_service_bpf_controller::{
    start_bpf_meshendpoint_controller, start_bpf_service_controller,
};
pub use state::{ServiceEndpointBpfMap, ServiceEndpointState as BpfServiceEndpointState};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Result,
    bpf::{
        BPF_MAP_ENDPOINTS_V4, BPF_MAP_ENDPOINTS_V6, BPF_MAP_SERVICES_V4, BPF_MAP_SERVICES_V6,
        service::{api::Server, state::ServiceEndpoint},
    },
    kubernetes::ClusterId,
};

type ServiceEndpointV4 = ServiceEndpoint<
    HashMap<MapData, ServiceKeyV4, ServiceValue>,
    HashMap<MapData, EndpointKey, EndpointValueV4>,
    ServiceKeyV4,
    EndpointValueV4,
>;
type ServiceEndpointV6 = ServiceEndpoint<
    HashMap<MapData, ServiceKeyV6, ServiceValue>,
    HashMap<MapData, EndpointKey, EndpointValueV6>,
    ServiceKeyV6,
    EndpointValueV6,
>;
type ServiceMapV4 = HashMap<MapData, ServiceKeyV4, ServiceValue>;
type ServiceMapV6 = HashMap<MapData, ServiceKeyV6, ServiceValue>;
type EndpointMapV4 = HashMap<MapData, EndpointKey, EndpointValueV4>;
type EndpointMapV6 = HashMap<MapData, EndpointKey, EndpointValueV6>;

pub async fn run(
    kube_client: Client,
    _cluster_id: ClusterId,
    cancel: CancellationToken,
) -> Result<ServiceServer<Server<ServiceEndpointV4, ServiceEndpointV6>>> {
    let (service_map_v4, service_map_v6) = load_service_maps()?;
    let (endpoint_map_v4, endpoint_map_v6) = load_endpoint_maps()?;

    info!("loaded bpf maps");

    let service_endpoint_v4 = ServiceEndpoint::new(service_map_v4, endpoint_map_v4);
    let service_endpoint_v6 = ServiceEndpoint::new(service_map_v6, endpoint_map_v6);

    let state = state::ServiceEndpointState::new(service_endpoint_v4, service_endpoint_v6);
    let server = Server::new(state.clone());
    let server = mesh_cni_api::service::v1::service_server::ServiceServer::new(server);

    let service_api: Api<Service> = Api::all(kube_client.clone());
    let (service_state, service_subscriber) =
        create_store_and_subscriber(service_api, Some(Duration::from_secs(30))).await?;

    let endpoint_slice_api: Api<EndpointSlice> = Api::all(kube_client.clone());
    let (endpoint_slice_state, endpoint_slice_subscriber) =
        create_store_and_subscriber(endpoint_slice_api, Some(Duration::from_secs(30))).await?;

    let mesh_endpoint_api = Api::all(kube_client.clone());
    let (mesh_endpoint_state, _) =
        create_store_and_subscriber(mesh_endpoint_api.clone(), Some(Duration::from_secs(30)))
            .await?;

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

fn load_service_maps() -> Result<(ServiceMapV4, ServiceMapV6)> {
    info!("loading v4 service map");
    let ipv4_map = MapData::from_pin(BPF_MAP_SERVICES_V4.path())?;
    let ipv4_map = Map::HashMap(ipv4_map);
    let ipv4_map = ipv4_map.try_into()?;

    info!("loading v6 service map");
    let ipv6_map = MapData::from_pin(BPF_MAP_SERVICES_V6.path())?;
    let ipv6_map = Map::HashMap(ipv6_map);
    let ipv6_map = ipv6_map.try_into()?;

    Ok((ipv4_map, ipv6_map))
}

fn load_endpoint_maps() -> Result<(EndpointMapV4, EndpointMapV6)> {
    info!("loading v4 endpoint map");
    let ipv4_map = MapData::from_pin(BPF_MAP_ENDPOINTS_V4.path())?;
    let ipv4_map = Map::HashMap(ipv4_map);
    let ipv4_map = ipv4_map.try_into()?;

    info!("loading v6 endpoint map");
    let ipv6_map = MapData::from_pin(BPF_MAP_ENDPOINTS_V6.path())?;
    let ipv6_map = Map::HashMap(ipv6_map);
    let ipv6_map = ipv6_map.try_into()?;

    Ok((ipv4_map, ipv6_map))
}
