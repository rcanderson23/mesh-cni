mod server;
mod state;
pub use state::{IpNetwork, IpNetworkState, IpNetworkV4, IpNetworkV6};

use aya::maps::lpm_trie::Key as LpmKey;
use kube::Client;
use mesh_cni_api::ip::v1::ip_server::IpServer;
use mesh_cni_common::Id;
use tokio_util::sync::CancellationToken;

use crate::Result;
use crate::bpf::BpfMap;
use crate::bpf::ip::server::Server;
use crate::kubernetes::ClusterId;
use crate::kubernetes::controllers::start_ip_controllers;

pub async fn run<IP4, IP6>(
    ipv4_map: IP4,
    ipv6_map: IP6,
    kube_client: Client,
    cluster_id: ClusterId,
    cancel: CancellationToken,
) -> Result<IpServer<Server<IP4, IP6>>>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = Id> + Send + 'static,
    IP6: BpfMap<Key = LpmKey<u128>, Value = Id> + Send + 'static,
{
    let state = IpNetworkState::new(ipv4_map, ipv6_map);
    let controllers = start_ip_controllers(kube_client, state.clone(), cluster_id, cancel);
    let server = Server::new(state);
    let server = mesh_cni_api::ip::v1::ip_server::IpServer::new(server);

    tokio::spawn(controllers);
    Ok(server)
}
