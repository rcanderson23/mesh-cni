pub mod bpf;
pub mod ip;
pub mod metrics;

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use mesh_cni_api::bpf::v1::bpf_server::BpfServer;
use mesh_cni_api::ip::v1::ip_server::IpServer;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::service::{Routes, RoutesBuilder};
use tonic::transport::Server;
use tracing::{error, info};

use crate::agent::ip::IpServ;
use crate::config::ControllerArgs;
use crate::http::shutdown;
use crate::kubernetes::pod::NamespacePodState;
use crate::{Error, Result};

// TODO: make this configurable?
const POD_IDENTITY_CAPACITY: usize = 1000;

pub async fn start(args: ControllerArgs, cancel: CancellationToken) -> Result<()> {
    let (pod_id_tx, pod_id_rx) = tokio::sync::mpsc::channel(POD_IDENTITY_CAPACITY);

    // TODO: configure this dynamically for all clusters configured in mesh
    let kube_client = kube::Client::try_default().await?;
    let ns_pod_state = NamespacePodState::try_new(kube_client, args.cluster_id, pod_id_tx).await?;
    let ns_pod_handle = ns_pod_state.start();

    let bpf = bpf::State::try_new()?;

    // TODO: bpf maps should be pinned and loaded from pinned location
    let ip_id = bpf
        .take_map("IP_IDENTITY")
        .await
        .ok_or_else(|| Error::MapNotFound {
            name: "IP_IDENTITY".into(),
        })?
        .try_into()?;

    let ipserv = IpServ::from(ip_id, pod_id_rx).await;
    // TODO: consolidate all state routers for single listener
    let bpf_server = BpfServer::new(bpf);
    let ip_server = IpServer::new(ipserv);

    let mut routes = RoutesBuilder::default();
    let routes = routes.add_service(bpf_server).add_service(ip_server);
    let routes = routes.to_owned().routes();
    let server_handle = serve(args.agent_socket_path, routes, cancel.child_token());
    tokio::select! {
        _ = cancel.cancelled() => {},
        h = server_handle => exit("bpf", h),
        h = ns_pod_handle => exit("ns", h),
    }
    Ok(())
}

fn exit(task: &str, out: Result<()>) {
    match out {
        Ok(_) => {
            info!("{task} exited")
        }
        Err(e) => {
            error!("{task} failed with error: {e}")
        }
    }
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
