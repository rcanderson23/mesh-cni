mod server;
mod state;
use aya::maps::{LpmTrie, Map, MapData};
pub use state::{IpNetwork, IpNetworkState, IpNetworkV4, IpNetworkV6};

use kube::Client;
use mesh_cni_api::ip::v1::ip_server::IpServer;
use mesh_cni_ebpf_common::Id;
use tokio_util::sync::CancellationToken;

use crate::Result;
use crate::bpf::ip::server::Server;
use crate::bpf::{BPF_MAP_IDENTITY_V4, BPF_MAP_IDENTITY_V6, IdentityMapV4, IdentityMapV6};
use crate::kubernetes::ClusterId;
use crate::kubernetes::controllers::start_ip_controllers;

pub async fn run(
    kube_client: Client,
    cluster_id: ClusterId,
    cancel: CancellationToken,
) -> Result<IpServer<Server<IdentityMapV4, IdentityMapV6>>> {
    let (ipv4_map, ipv6_map) = load_maps()?;

    let state = IpNetworkState::new(ipv4_map, ipv6_map);
    let controllers = start_ip_controllers(kube_client, state.clone(), cluster_id, cancel);
    let server = Server::new(state);
    let server = mesh_cni_api::ip::v1::ip_server::IpServer::new(server);

    tokio::spawn(controllers);
    Ok(server)
}

fn load_maps() -> Result<(IdentityMapV4, IdentityMapV6)> {
    let ipv4_map = MapData::from_pin(BPF_MAP_IDENTITY_V4.path())?;
    let ipv4_map = Map::LpmTrie(ipv4_map);
    let ipv4_map: LpmTrie<MapData, u32, Id> = ipv4_map.try_into()?;

    let ipv6_map = MapData::from_pin(BPF_MAP_IDENTITY_V6.path())?;
    let ipv6_map = Map::LpmTrie(ipv6_map);
    let ipv6_map: LpmTrie<MapData, u128, Id> = ipv6_map.try_into()?;

    Ok((ipv4_map, ipv6_map))
}
