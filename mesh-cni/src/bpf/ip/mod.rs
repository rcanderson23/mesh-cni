mod convert;
mod server;
mod state;
use aya::maps::{LpmTrie, Map, MapData};
pub(crate) use convert::LpmKeyNetwork;
use kube::Client;
use mesh_cni_api::ip::v1::ip_server::IpServer;
use mesh_cni_ebpf_common::IdentityId;
use mesh_cni_identity_controller::start_identity_controllers;
pub use state::IpNetworkState;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Result,
    bpf::{
        BPF_MAP_IDENTITY_V4, BPF_MAP_IDENTITY_V6, IdentityMapV4, IdentityMapV6, ip::server::Server,
    },
};

pub async fn run(
    kube_client: Client,
    node_name: String,
    cancel: CancellationToken,
) -> Result<IpServer<Server<IdentityMapV4, IdentityMapV6>>> {
    info!("loading maps");
    let (ipv4_map, ipv6_map) = load_maps()?;

    info!("creating new network state");
    let state = IpNetworkState::new(ipv4_map, ipv6_map);
    let controllers = start_identity_controllers(kube_client, node_name, cancel, state.clone());
    let server = Server::new(state);
    let server = mesh_cni_api::ip::v1::ip_server::IpServer::new(server);

    tokio::spawn(controllers);
    Ok(server)
}

fn load_maps() -> Result<(IdentityMapV4, IdentityMapV6)> {
    info!("loading v4 identity map");
    let ipv4_map = MapData::from_pin(BPF_MAP_IDENTITY_V4.path())?;
    let ipv4_map = Map::LpmTrie(ipv4_map);
    info!("converting v4 identity map");
    let ipv4_map: LpmTrie<MapData, u32, IdentityId> = ipv4_map.try_into()?;

    info!("loading v6 identity map");
    let ipv6_map = MapData::from_pin(BPF_MAP_IDENTITY_V6.path())?;
    let ipv6_map = Map::LpmTrie(ipv6_map);
    let ipv6_map: LpmTrie<MapData, u128, IdentityId> = ipv6_map.try_into()?;

    Ok((ipv4_map, ipv6_map))
}
