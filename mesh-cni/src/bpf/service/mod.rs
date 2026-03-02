mod nodeport_iface;
mod state;

use std::sync::Arc;

use aya::maps::{HashMap, Map, MapData};
use kube::Client;
use mesh_cni_ebpf_common::service::{
    EndpointKey, EndpointValueV4, EndpointValueV6, NodePortFrontendValue, NodePortKey,
    ServiceKeyV4, ServiceKeyV6, ServiceValue,
};
use mesh_cni_service_bpf_controller::{ServiceBpfState, start_bpf_service_controller};
pub use state::{
    ControllerServiceBpfState, NodePortState, ServiceEndpoint, ServiceEndpointBpfMap,
    ServiceEndpointState,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    Result,
    bpf::{
        BPF_MAP_ENDPOINTS_V4, BPF_MAP_ENDPOINTS_V6, BPF_MAP_NODEPORT_POLICIES_V4,
        BPF_MAP_NODEPORT_POLICIES_V6, BPF_MAP_NODEPORTS_V4, BPF_MAP_NODEPORTS_V6,
        BPF_MAP_SERVICES_V4, BPF_MAP_SERVICES_V6,
    },
    config::NodePortSettings,
};
type ServiceMapV4 = HashMap<MapData, ServiceKeyV4, ServiceValue>;
type ServiceMapV6 = HashMap<MapData, ServiceKeyV6, ServiceValue>;
type EndpointMapV4 = HashMap<MapData, EndpointKey, EndpointValueV4>;
type EndpointMapV6 = HashMap<MapData, EndpointKey, EndpointValueV6>;
type NodePortFrontendMapV4 = HashMap<MapData, NodePortKey, ServiceKeyV4>;
type NodePortFrontendMapV6 = HashMap<MapData, NodePortKey, ServiceKeyV6>;
type NodePortPolicyMapV4 = HashMap<MapData, NodePortKey, NodePortFrontendValue>;
type NodePortPolicyMapV6 = HashMap<MapData, NodePortKey, NodePortFrontendValue>;

pub async fn run<B>(
    kube_client: Client,
    node_name: String,
    service_bpf_state: B,
    node_port_settings: NodePortSettings,
    cancel: CancellationToken,
) -> Result<()>
where
    B: ServiceBpfState + Send + Sync + 'static,
{
    let service_bpf_state = Arc::new(service_bpf_state);
    let service_cancel = cancel.child_token();
    tokio::spawn(async move {
        let mut backoff = std::time::Duration::from_secs(2);
        loop {
            if service_cancel.is_cancelled() {
                break;
            }
            let run_result = start_bpf_service_controller(
                kube_client.clone(),
                node_name.clone(),
                service_bpf_state.clone(),
                service_cancel.child_token(),
            )
            .await;

            if service_cancel.is_cancelled() {
                break;
            }
            match run_result {
                Ok(()) => {
                    warn!("service controller exited; restarting");
                }
                Err(err) => {
                    warn!(%err, "service controller startup/runtime failed; retrying");
                }
            }
            tokio::select! {
                _ = service_cancel.cancelled() => break,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = std::cmp::min(backoff * 2, std::time::Duration::from_secs(30));
        }
    });

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

pub fn load_nodeport_maps() -> Result<(NodePortFrontendMapV4, NodePortFrontendMapV6)> {
    info!("loading v4 nodeport frontend map");
    let ipv4_map = MapData::from_pin(BPF_MAP_NODEPORTS_V4.path())?;
    let ipv4_map = Map::HashMap(ipv4_map);
    let ipv4_map = ipv4_map.try_into()?;

    info!("loading v6 nodeport frontend map");
    let ipv6_map = MapData::from_pin(BPF_MAP_NODEPORTS_V6.path())?;
    let ipv6_map = Map::HashMap(ipv6_map);
    let ipv6_map = ipv6_map.try_into()?;

    Ok((ipv4_map, ipv6_map))
}

pub fn load_nodeport_policy_maps() -> Result<(NodePortPolicyMapV4, NodePortPolicyMapV6)> {
    info!("loading v4 nodeport policy map");
    let ipv4_map = MapData::from_pin(BPF_MAP_NODEPORT_POLICIES_V4.path())?;
    let ipv4_map = Map::HashMap(ipv4_map);
    let ipv4_map = ipv4_map.try_into()?;

    info!("loading v6 nodeport policy map");
    let ipv6_map = MapData::from_pin(BPF_MAP_NODEPORT_POLICIES_V6.path())?;
    let ipv6_map = Map::HashMap(ipv6_map);
    let ipv6_map = ipv6_map.try_into()?;

    Ok((ipv4_map, ipv6_map))
}
