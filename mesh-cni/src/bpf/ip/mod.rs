mod server;
mod state;

use kube::Client;
use mesh_cni_api::ip::v1::ip_server::IpServer;
use mesh_cni_common::Id;
use tokio::task::JoinHandle;

use crate::Result;
use crate::bpf::BpfMap;
use crate::bpf::ip::server::Server;
use crate::bpf::ip::state::State;
use crate::kubernetes::ClusterId;
use crate::kubernetes::pod::NamespacePodState;

pub async fn run<I, P>(
    ipv4_map: I,
    ipv6_map: P,
    kube_client: Client,
    cluster_id: ClusterId,
) -> Result<(IpServer<Server<I, P>>, JoinHandle<Result<()>>)>
where
    I: BpfMap<u32, Id> + Send + 'static,
    P: BpfMap<u128, Id> + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(1000);
    let ns_pod_state = NamespacePodState::try_new(kube_client, cluster_id, tx).await?;
    let state = State::new(ipv4_map, ipv6_map);
    let server = Server::from(state, rx).await;
    let server = mesh_cni_api::ip::v1::ip_server::IpServer::new(server);

    let h = tokio::spawn(async move { ns_pod_state.start().await });
    Ok((server, h))
}
