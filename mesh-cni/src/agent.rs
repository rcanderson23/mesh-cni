use std::sync::{Arc, Mutex};

use anyhow::bail;
use mesh_cni_api::cni::v1::cni_server::CniServer;
use mesh_cni_vxlan_controller::start_vxlan_controller;
use tokio_util::sync::CancellationToken;
use tonic::service::RoutesBuilder;
use tracing::{error, info};

use crate::{
    Result,
    bpf::{
        self,
        ip::IpNetworkState,
        policy::{PolicyBpfState, PolicyState},
        service::{ServiceEndpoint, ServiceEndpointState},
    },
    config::{AgentArgs, CniMode},
    http,
    ipam::{self},
    kubernetes, system,
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
    bpf::loader::init_bpf(&args.cni_settings.mode)?;

    info!("starting policy service");
    let policy_state = PolicyBpfState::try_new()?;
    let policy_state = PolicyState::new(
        policy_state.index(),
        policy_state.ruleset(),
        policy_state.cidr_v4(),
        policy_state.cidr_v6(),
    );
    let policy_context =
        bpf::policy::run(kube_client.clone(), policy_state.clone(), cancel.clone()).await?;
    let policy_server = http::grpc::policy::server(policy_state.clone());

    let routes_map = bpf::routes::load_routes_map()?;
    let routes_state = bpf::routes::RoutesState::try_new(routes_map)?;
    let mut vxlan_controller_handle = None;

    info!("starting cni service");
    let cni_server = match args.cni_settings.mode {
        CniMode::Chained => {
            let cni_state = http::grpc::cni::CniState::new(
                policy_context,
                Arc::new(Mutex::new(ipam::Ipam::Noop(ipam::NoopIpam))),
                routes_state,
            );
            CniServer::new(cni_state)
        }
        CniMode::Vxlan => {
            let vxlan_ifindex = system::ensure_vxlan(&args.vxlan_settings).await?;
            let ipam = ipam::get_ipamv4_from_node(kube_client.clone(), &args.node_name).await?;
            let ipam = Arc::new(Mutex::new(ipam::Ipam::V4(ipam)));

            vxlan_controller_handle = Some(tokio::spawn(start_vxlan_controller(
                kube_client.clone(),
                args.node_name.clone(),
                routes_state.clone(),
                vxlan_ifindex,
                cancel.child_token(),
            )));
            let cni_state = http::grpc::cni::CniState::new(policy_context, ipam, routes_state);

            CniServer::new(cni_state)
        }
    };

    info!("loading ip maps");
    let (ipv4_map, ipv6_map) = bpf::ip::load_maps()?;
    let state = IpNetworkState::try_new(ipv4_map, ipv6_map)?;

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
    let nodeport_service_map = bpf::service::load_nodeport_service_map()?;

    info!("starting kube service service");
    let service_endpoint_v4 = ServiceEndpoint::try_new(service_map_v4, endpoint_map_v4)?;
    let service_endpoint_v6 = ServiceEndpoint::try_new(service_map_v6, endpoint_map_v6)?;
    let state = ServiceEndpointState::new(
        service_endpoint_v4,
        service_endpoint_v6,
        nodeport_service_map,
    )?;
    bpf::service::run(
        kube_client.clone(),
        state.clone(),
        args.proxy_settings.node_port_settings.clone(),
        cancel.clone(),
    )
    .await?;
    let service_server = http::grpc::service::server(state);

    info!("starting conntrack cleanup background process");
    let cleanup_handle = tokio::spawn(bpf::conntrack::run_cleanup(cancel.clone()));
    let conntrack_server = http::grpc::conntrack::server();

    let mut routes = RoutesBuilder::default();
    let routes = routes
        .add_service(cni_server)
        .add_service(ip_server)
        .add_service(service_server)
        .add_service(policy_server)
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
    kubernetes::node::remove_startup_taint(kube_client.clone(), args.node_name.clone()).await?;
    if args.cni_settings.mode == CniMode::Vxlan {
        kubernetes::node::set_network_ready(kube_client, args.node_name).await?;
    }

    // TODO: do something else than a cancellation token for readiness probe
    ready.cancel();

    // TODO: add graceful shutdown
    if let Some(vxlan_controller_handle) = vxlan_controller_handle {
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
            },
            h = vxlan_controller_handle => {
                match h {
                    Ok(Ok(_)) => info!("vxlan controller exited gracefully"),
                    Ok(Err(e)) => {
                        error!(%e, "vxlan controller exited with error");
                        return Err(anyhow::Error::from(e));
                    },
                    Err(e) => {
                        error!(%e, "failed to join vxlan controller task");
                        bail!("failed to join tasks");
                    },
                }
            }
        }
    } else {
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
    }
    Ok(())
}
