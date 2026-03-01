mod nodeport_iface;
mod state;

use aya::maps::{HashMap, Map, MapData};
use kube::Client;
use mesh_cni_ebpf_common::service::{
    EndpointKey, EndpointValueV4, EndpointValueV6, ServiceKeyV4, ServiceKeyV6, ServiceValue,
};
use mesh_cni_service_bpf_controller::start_bpf_service_controller;
pub use state::{ServiceEndpoint, ServiceEndpointBpfMap, ServiceEndpointState};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Result,
    bpf::{BPF_MAP_ENDPOINTS_V4, BPF_MAP_ENDPOINTS_V6, BPF_MAP_SERVICES_V4, BPF_MAP_SERVICES_V6},
    config::NodePortSettings,
};
type ServiceMapV4 = HashMap<MapData, ServiceKeyV4, ServiceValue>;
type ServiceMapV6 = HashMap<MapData, ServiceKeyV6, ServiceValue>;
type EndpointMapV4 = HashMap<MapData, EndpointKey, EndpointValueV4>;
type EndpointMapV6 = HashMap<MapData, EndpointKey, EndpointValueV6>;

pub async fn run<SE4, SE6>(
    kube_client: Client,
    service_bpf_state: ServiceEndpointState<SE4, SE6>,
    node_port_settings: NodePortSettings,
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
    let service_controller =
        start_bpf_service_controller(kube_client, service_bpf_state, cancel.child_token());

    tokio::spawn(service_controller);
    nodeport_iface::start_nodeport_iface_reconciler(node_port_settings, cancel.child_token())?;

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
