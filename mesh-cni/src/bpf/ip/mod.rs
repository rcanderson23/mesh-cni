mod server;
mod state;
pub use state::{IpNetwork, IpNetworkV4, IpNetworkV6};

use aya::maps::lpm_trie::Key as LpmKey;
use kube::Client;
use mesh_cni_api::ip::v1::ip_server::IpServer;
use mesh_cni_common::Id;
use tokio::task::JoinHandle;

use crate::Result;
use crate::bpf::BpfMap;
use crate::bpf::ip::server::Server;
use crate::bpf::ip::state::IpNetworkState;
use crate::kubernetes::ClusterId;
use crate::kubernetes::pod::NamespacePodState;

pub async fn run<IP4, IP6>(
    ipv4_map: IP4,
    ipv6_map: IP6,
    kube_client: Client,
    cluster_id: ClusterId,
) -> Result<(IpServer<Server<IP4, IP6>>, JoinHandle<Result<()>>)>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = Id> + Send + 'static,
    IP6: BpfMap<Key = LpmKey<u128>, Value = Id> + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(1000);
    let ns_pod_state = NamespacePodState::try_new(kube_client, cluster_id, tx).await?;
    let state = IpNetworkState::new(ipv4_map, ipv6_map);
    let server = Server::from(state, rx).await;
    let server = mesh_cni_api::ip::v1::ip_server::IpServer::new(server);

    let h = tokio::spawn(async move { ns_pod_state.start().await });
    Ok((server, h))
}
