mod state;

use std::time::Duration;

use aya::maps::{HashMap, Map, MapData};
use k8s_openapi::api::{core::v1::Service, discovery::v1::EndpointSlice};
use kube::{Api, Client};
use mesh_cni_ebpf_common::service::{
    EndpointKey, EndpointValueV4, EndpointValueV6, ServiceKeyV4, ServiceKeyV6, ServiceValue,
};
use mesh_cni_k8s_utils::create_store_and_subscriber;
use mesh_cni_service_bpf_controller::{
    start_bpf_meshendpoint_controller, start_bpf_service_controller,
};
pub use state::{ServiceEndpoint, ServiceEndpointBpfMap, ServiceEndpointState};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Result,
    bpf::{BPF_MAP_ENDPOINTS_V4, BPF_MAP_ENDPOINTS_V6, BPF_MAP_SERVICES_V4, BPF_MAP_SERVICES_V6},
};
type ServiceMapV4 = HashMap<MapData, ServiceKeyV4, ServiceValue>;
type ServiceMapV6 = HashMap<MapData, ServiceKeyV6, ServiceValue>;
type EndpointMapV4 = HashMap<MapData, EndpointKey, EndpointValueV4>;
type EndpointMapV6 = HashMap<MapData, EndpointKey, EndpointValueV6>;

pub async fn run<SE4, SE6>(
    kube_client: Client,
    service_bpf_state: ServiceEndpointState<SE4, SE6>,
    cancel: CancellationToken,
) -> Result<()>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>
        + Send
        + Sync
        + 'static,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>
        + Send
        + Sync
        + 'static,
{
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
        service_bpf_state.clone(),
        cancel.clone(),
    );

    let mesh_endpoint_controller = start_bpf_meshendpoint_controller(
        mesh_endpoint_api,
        service_state,
        endpoint_slice_state,
        mesh_endpoint_state,
        service_bpf_state,
        cancel.clone(),
    );
    tokio::spawn(service_controller);
    tokio::spawn(mesh_endpoint_controller);

    Ok(())
}

pub fn load_service_maps() -> Result<(ServiceMapV4, ServiceMapV6)> {
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

pub fn load_endpoint_maps() -> Result<(EndpointMapV4, EndpointMapV6)> {
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
