use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use mesh_cni_api::bpf::v1::bpf_server::BpfServer;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::service::{Routes, RoutesBuilder};
use tonic::transport::Server;
use tracing::info;

use crate::config::AgentArgs;
use crate::http::shutdown;
use crate::kubernetes::cluster::{Cluster, ClusterConfigs};
use crate::{Result, bpf, kubernetes};

pub async fn start(
    args: AgentArgs,
    ready: CancellationToken,
    cancel: CancellationToken,
) -> Result<()> {
    info!("loading cluster configs");
    let configs = ClusterConfigs::try_new_configs(args.mesh_clusters_config).await?;
    let mut local_cluster = Cluster::try_new(configs.local).await?;
    let kube_client = local_cluster.take_client().unwrap();

    info!("initializing bpf loader");
    let loader = bpf::loader::LoaderState::try_new()?;

    info!("initializing ip server");
    let ip_server = bpf::ip::run(kube_client.clone(), local_cluster.id, cancel.clone()).await?;

    info!("initializing service server");
    let service_server =
        bpf::service::run(kube_client.clone(), local_cluster.id, cancel.clone()).await?;

    info!("initializing bpf server");
    let bpf_server = BpfServer::new(loader);

    let mut routes = RoutesBuilder::default();
    let routes = routes
        .add_service(bpf_server)
        .add_service(ip_server)
        .add_service(service_server);
    let routes = routes.to_owned().routes();
    tokio::spawn(serve(args.agent_socket_path, routes, cancel.child_token()));

    // TODO: move to something less brittle
    info!("removing node taint");
    kubernetes::node::remove_startup_taint(kube_client, args.node_name).await?;
    ready.cancel();
    // TODO: add graceful shutdown
    tokio::select! {
        _ = cancel.cancelled() => {},
    }
    Ok(())
}

pub(crate) async fn serve(path: PathBuf, routes: Routes, cancel: CancellationToken) -> Result<()> {
    if let Err(e) = fs::remove_file(&path)
        && e.kind() != ErrorKind::NotFound
    {
        return Err(e.into());
    }
    let Some(parent) = path.parent() else {
        return Err(std::io::Error::new(
            ErrorKind::NotFound,
            format!("parent of path {} could not resolve", path.display()),
        )
        .into());
    };
    fs::create_dir_all(parent)?;
    let listener = UnixListener::bind(&path)?;

    let stream = UnixListenerStream::new(listener);

    Server::builder()
        .add_routes(routes)
        .serve_with_incoming_shutdown(stream, shutdown(cancel))
        .await?;

    Ok(())
}
