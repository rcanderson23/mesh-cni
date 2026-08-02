mod state;

use aya::maps::{HashMap as AyaHashMap, Map, MapData};
use kube::Client;
use mesh_cni_ebpf_common::hostport::{HostPortKeyV4, HostPortValueV4};
use mesh_cni_hostport_bpf_controller::start_hostport_bpf_service_controller;
pub use state::HostPortState;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Result,
    bpf::{BPF_MAP_HOSTPORT_V4, BpfMap},
};

type HostPortMapV4 = AyaHashMap<MapData, HostPortKeyV4, HostPortValueV4>;

pub async fn run<M>(
    kube_client: Client,
    hostport_bpf_state: HostPortState<M>,
    node_name: String,
    cancel: CancellationToken,
) -> Result<()>
where
    M: BpfMap<Key = HostPortKeyV4, Value = HostPortValueV4, KeyOutput = HostPortKeyV4>
        + Send
        + 'static,
{
    tokio::spawn(async move {
        start_hostport_bpf_service_controller(
            kube_client,
            hostport_bpf_state,
            &node_name,
            cancel.child_token(),
        )
        .await
    });
    Ok(())
}

pub fn load_hostport_v4_map() -> Result<HostPortMapV4> {
    info!("loading hostport v4 map");
    let map = MapData::from_pin(BPF_MAP_HOSTPORT_V4.path())?;
    let map = Map::HashMap(map);
    let map = map.try_into()?;
    Ok(map)
}
