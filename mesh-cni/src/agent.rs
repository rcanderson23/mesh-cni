use anyhow::bail;
use mesh_cni_api::cni::v1::cni_server::CniServer;
use tokio_util::sync::CancellationToken;
use tonic::service::RoutesBuilder;
use tracing::{error, info};

use crate::{
    Result,
    bpf::{
        self,
        ip::IpNetworkState,
        service::{ServiceEndpoint, ServiceEndpointState},
    },
    config::AgentArgs,
    http, kubernetes,
};

pub async fn start(
    args: AgentArgs,
    ready: CancellationToken,
    cancel: CancellationToken,
) -> Result<()> {
    info!("loading cluster configs");
    let mut config = kube::Config::infer().await?;
    config.cluster_url = args.cluster_url;
    let kube_client = kube::Client::try_from(config)?;

    info!("initializing bpf");
    bpf::loader::init_bpf()?;

    info!("starting cni service");
    let loader = http::grpc::cni::LoaderState;
    let cni_server = CniServer::new(loader);

    info!("loading ip maps");
    let (ipv4_map, ipv6_map) = bpf::ip::load_maps()?;
    let state = IpNetworkState::new(ipv4_map, ipv6_map);

    info!("starting ip service");
    bpf::ip::run(
        kube_client.clone(),
        args.node_name.clone(),
        state.clone(),
        cancel.clone(),
    )
    .await?;
    let ip_server = http::grpc::ip::server(state);

    info!("loading service/endpoint bpf maps");
    let (service_map_v4, service_map_v6) = bpf::service::load_service_maps()?;
    let (endpoint_map_v4, endpoint_map_v6) = bpf::service::load_endpoint_maps()?;

    info!("starting kube service service");
    let service_endpoint_v4 = ServiceEndpoint::new(service_map_v4, endpoint_map_v4);
    let service_endpoint_v6 = ServiceEndpoint::new(service_map_v6, endpoint_map_v6);
    let state = ServiceEndpointState::new(service_endpoint_v4, service_endpoint_v6);
    bpf::service::run(kube_client.clone(), state.clone(), cancel.clone()).await?;
    let service_server = http::grpc::service::server(state);

    info!("starting conntrack cleanup background process");
    let cleanup_handle = tokio::spawn(bpf::conntrack::run_cleanup(cancel.clone()));
    let conntrack_server = http::grpc::conntrack::server();

    let mut routes = RoutesBuilder::default();
    let routes = routes
        .add_service(cni_server)
        .add_service(ip_server)
        .add_service(service_server)
        .add_service(conntrack_server);
    let routes = routes.to_owned().routes();

    info!("starting gprc server");
    let grpc_handle = tokio::spawn(http::grpc::serve(
        args.agent_socket_path,
        routes,
        cancel.child_token(),
    ));

    // TODO: move to something less brittle
    info!("removing node taint");
    kubernetes::node::remove_startup_taint(kube_client, args.node_name).await?;

    // TODO: do something else than a cancellation token for readiness probe
    ready.cancel();

    // TODO: add graceful shutdown
    tokio::select! {
        _ = cancel.cancelled() => {},
        h = grpc_handle => {
            match h {
                Ok(Ok(_)) => info!("grpc task exited gracefully"),
                Ok(Err(e)) => {
                    error!(%e, "grpc exited with error");
                    return Err(e);
                },
                Err(e) => {
                    error!(%e);
                    bail!("failed to join tasks");
                },
            }
        },
        h = cleanup_handle => {
            match h {
                Ok(Ok(_)) => info!("cleanup exited gracefully"),
                Ok(Err(e)) => {
                    error!(%e, "cleanup exited with error");
                    return Err(e);
                },
                Err(e) => {
                    error!(%e);
                    bail!("failed to join tasks");
                },
            }

        }
    }
    Ok(())
}
