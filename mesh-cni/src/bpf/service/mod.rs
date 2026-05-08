mod nodeport_iface;
mod state;

use aya::maps::{HashMap, Map, MapData};
use kube::Client;
use mesh_cni_ebpf_common::service::{
    EndpointKey, EndpointValueV4, EndpointValueV6, NodePortKey, ServiceKeyV4, ServiceKeyV6,
    ServiceValue,
};
use mesh_cni_service_bpf_controller::start_bpf_service_controller;
pub use state::{EndpointMapStore, ServiceEndpoint, ServiceEndpointState, ServiceMapStore};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Result,
    bpf::{
        BPF_MAP_ENDPOINTS_V4, BPF_MAP_ENDPOINTS_V6, BPF_MAP_NODEPORT_SERVICES_V4,
        BPF_MAP_SERVICES_V4, BPF_MAP_SERVICES_V6,
    },
    config::{CniMode, NodePortSettings},
};
type ServiceMapV4 = HashMap<MapData, ServiceKeyV4, ServiceValue>;
type ServiceMapV6 = HashMap<MapData, ServiceKeyV6, ServiceValue>;
type EndpointMapV4 = HashMap<MapData, EndpointKey, EndpointValueV4>;
type EndpointMapV6 = HashMap<MapData, EndpointKey, EndpointValueV6>;
type NodePortServiceMapV4 = HashMap<MapData, NodePortKey, ServiceKeyV4>;

pub async fn run<SE4, SE6, NP>(
    kube_client: Client,
    service_bpf_state: ServiceEndpointState<SE4, SE6, NP>,
    node_port_settings: NodePortSettings,
    cni_mode: CniMode,
    cancel: CancellationToken,
) -> Result<()>
where
    SE4: ServiceMapStore<SKey = ServiceKeyV4>
        + EndpointMapStore<EValue = EndpointValueV4>
        + Send
        + Sync
        + 'static,
    SE6: ServiceMapStore<SKey = ServiceKeyV6>
        + EndpointMapStore<EValue = EndpointValueV6>
        + Send
        + Sync
        + 'static,
    NP: crate::bpf::BpfMap<Key = NodePortKey, Value = ServiceKeyV4, KeyOutput = NodePortKey>
        + Send
        + Sync
        + 'static,
{
    let service_controller =
        start_bpf_service_controller(kube_client, service_bpf_state, cancel.child_token());

    tokio::spawn(service_controller);
    nodeport_iface::start_nodeport_iface_reconciler(
        node_port_settings,
        cni_mode,
        cancel.child_token(),
    )
    .await?;

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

pub fn load_nodeport_service_map() -> Result<NodePortServiceMapV4> {
    info!("loading nodeport service map");
    let map = MapData::from_pin(BPF_MAP_NODEPORT_SERVICES_V4.path())?;
    let map = Map::HashMap(map);
    let map = map.try_into()?;
    Ok(map)
}
