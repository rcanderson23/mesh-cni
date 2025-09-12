pub mod metrics;

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use ahash::HashMapExt;
use aya::maps::{HashMap, MapData};
use mesh_cni_api::bpf::v1::bpf_server::BpfServer;
use mesh_cni_api::service::v1::service_server::ServiceServer;
use mesh_cni_common::Id;
use mesh_cni_common::service::{
    EndpointKey, EndpointValueV4, EndpointValueV6, ServiceKeyV4, ServiceKeyV6, ServiceValue,
};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::service::{Routes, RoutesBuilder};
use tonic::transport::Server;
use tracing::{error, info};

use crate::config::AgentArgs;
use crate::http::shutdown;
use crate::{Error, Result, bpf};

pub async fn start(args: AgentArgs, cancel: CancellationToken) -> Result<()> {
    // TODO: configure this dynamically for all clusters configured in mesh
    let kube_client = kube::Client::try_default().await?;
    let loader = bpf::loader::LoaderState::try_new()?;

    // TODO: bpf maps should be pinned and loaded from pinned location
    let ipv4_map: HashMap<MapData, u32, Id> = loader
        .take_map("IPV4_IDENTITY")
        .await
        .ok_or_else(|| Error::MapNotFound {
            name: "IPV4_IDENTITY".into(),
        })?
        .try_into()?;
    let ipv6_map: HashMap<MapData, u128, Id> = loader
        .take_map("IPV6_IDENTITY")
        .await
        .ok_or_else(|| Error::MapNotFound {
            name: "IPV6_IDENTITY".into(),
        })?
        .try_into()?;

    let service_map_v4: HashMap<MapData, ServiceKeyV4, ServiceValue> = loader
        .take_map("SERVICES_V4")
        .await
        .ok_or_else(|| Error::MapNotFound {
            name: "SERVICES_V4".into(),
        })?
        .try_into()?;

    let service_map_v6: HashMap<MapData, ServiceKeyV6, ServiceValue> = loader
        .take_map("SERVICES_V6")
        .await
        .ok_or_else(|| Error::MapNotFound {
            name: "SERVICES_V6".into(),
        })?
        .try_into()?;

    let endpoint_map_v4: HashMap<MapData, EndpointKey, EndpointValueV4> = loader
        .take_map("ENDPOINTS_V4")
        .await
        .ok_or_else(|| Error::MapNotFound {
            name: "ENDPOINTS_V6".into(),
        })?
        .try_into()?;

    let endpoint_map_v6: HashMap<MapData, EndpointKey, EndpointValueV6> = loader
        .take_map("ENDPOINTS_V6")
        .await
        .ok_or_else(|| Error::MapNotFound {
            name: "ENDPOINTS_V6".into(),
        })?
        .try_into()?;

    let (ip_server, ip_handle) =
        bpf::ip::run(ipv4_map, ipv6_map, kube_client.clone(), args.cluster_id).await?;
    let service_server = bpf::service::run(
        service_map_v4,
        service_map_v6,
        endpoint_map_v4,
        endpoint_map_v6,
        kube_client,
        args.cluster_id,
        cancel.clone(),
    )
    .await?;
    let bpf_server = BpfServer::new(loader);

    let mut routes = RoutesBuilder::default();
    let routes = routes
        .add_service(bpf_server)
        .add_service(ip_server)
        .add_service(service_server);
    let routes = routes.to_owned().routes();
    tokio::spawn(serve(args.agent_socket_path, routes, cancel.child_token()));
    tokio::spawn(ip_handle);

    // TODO: add graceful shutdown
    tokio::select! {
        _ = cancel.cancelled() => {},
        // h = server_handle => exit("bpf", h),
        // h = ip_handle => exit("ip", h.map_err(|e| Error::Task(e.to_string()))?),
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
