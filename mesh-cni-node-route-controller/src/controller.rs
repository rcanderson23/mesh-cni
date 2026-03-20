use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use futures::TryStreamExt;
use ipnetwork::IpNetwork;
use k8s_openapi::api::core::v1::Node;
use kube::{Resource, ResourceExt, runtime::controller::Action};
use rtnetlink::{
    RouteMessageBuilder,
    packet_route::{
        AddressFamily,
        neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage},
        route::{RouteAddress, RouteAttribute},
    },
};
use tracing::{error, info, warn};

use crate::{Error, Result, context::Context};

const DEFAULT_REQUEUE_DURATION: Duration = Duration::from_secs(300);
const ERROR_REQUEUE_DURATION: Duration = Duration::from_secs(5);

pub(crate) async fn reconcile(node: Arc<Node>, ctx: Arc<Context>) -> Result<Action> {
    info!(
        "started reconciling NodeRoute state for Node {}",
        node.name_any()
    );
    reconcile_all_node_routes(&ctx).await?;
    Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
}

pub(crate) async fn reconcile_all_node_routes(ctx: &Context) -> Result<()> {
    let desired_routes = desired_node_routes(&ctx.node_store.state(), &ctx.node_name)?;
    let desired_vtep_peers = desired_vtep_peers(&ctx.node_store.state(), &ctx.node_name)?;

    let current_routes = current_node_routes(ctx).await?;
    let current_vtep_peers = current_vtep_peers(ctx).await?;

    info!(
        desired_route_count = desired_routes.len(),
        current_route_count = current_routes.len(),
        desired_vtep_count = desired_vtep_peers.len(),
        current_vtep_count = current_vtep_peers.len(),
        "reconciling node overlay state"
    );

    for cidr in current_routes.difference(&desired_routes) {
        info!(%cidr, "removing vxlan route");
        remove_node_route(ctx, *cidr).await?;
    }

    for cidr in desired_routes.difference(&current_routes) {
        info!(%cidr, "adding vxlan route");
        upsert_node_route(ctx, *cidr).await?;
    }

    let current_vtep_ips: HashSet<_> = current_vtep_peers.keys().copied().collect();
    for destination in current_vtep_ips.difference(&desired_vtep_peers) {
        info!(%destination, "removing vxlan peer");
        let message = current_vtep_peers
            .get(destination)
            .expect("current_vtep_ips derived from current_vtep_peers keys");
        remove_vtep_peer(ctx, message.clone()).await?;
    }

    for destination in desired_vtep_peers.difference(&current_vtep_ips) {
        info!(%destination, "adding vxlan peer");
        upsert_vtep_peer(ctx, *destination).await?;
    }

    Ok(())
}

fn desired_node_routes(nodes: &[Arc<Node>], local_node_name: &str) -> Result<HashSet<IpNetwork>> {
    let mut routes = HashSet::default();

    for node in nodes {
        if node.name_any() == local_node_name || node.meta().deletion_timestamp.is_some() {
            continue;
        }

        for pod_cidr in node_pod_cidrs(node)? {
            routes.insert(pod_cidr);
        }
    }

    Ok(routes)
}

// TODO: implement ipv6
fn desired_vtep_peers(nodes: &[Arc<Node>], local_node_name: &str) -> Result<HashSet<IpAddr>> {
    let mut peers = HashSet::default();

    for node in nodes {
        if node.name_any() == local_node_name || node.meta().deletion_timestamp.is_some() {
            continue;
        }

        let Some(node_ip) = node_internal_ipv4(node)? else {
            warn!(
                node = %node.name_any(),
                "skipping vxlan peer reconcile for node without IPv4 InternalIP"
            );
            continue;
        };
        peers.insert(IpAddr::V4(node_ip));
    }

    Ok(peers)
}

// TODO: support v6
async fn current_node_routes(ctx: &Context) -> Result<HashSet<IpNetwork>> {
    let v4 = RouteMessageBuilder::<Ipv4Addr>::new().build();

    let mut routes = ctx.handle.route().get(v4).execute();
    let mut node_networks = HashSet::default();
    while let Some(route) = routes.try_next().await? {
        let Some(oif) = route_output_interface(&route.attributes) else {
            continue;
        };
        if oif != ctx.mesh_vxlan_ifindex {
            continue;
        }

        let Some(destination) =
            route_destination(&route.attributes, route.header.destination_prefix_length)?
        else {
            continue;
        };

        node_networks.insert(destination);
    }
    Ok(node_networks)
}

async fn current_vtep_peers(ctx: &Context) -> Result<HashMap<IpAddr, NeighbourMessage>> {
    let mut neighbours = ctx.handle.neighbours().get().execute();
    let mut vtep_peers = HashMap::default();

    while let Some(neighbour) = neighbours.try_next().await? {
        if neighbour.header.family != AddressFamily::Bridge
            || neighbour.header.ifindex != ctx.mesh_vxlan_ifindex
        {
            continue;
        }

        if !is_zero_mac_fdb(&neighbour.attributes) {
            continue;
        }

        let Some(destination) = neighbour_destination(&neighbour.attributes) else {
            continue;
        };

        info!(underlay_ip = %destination, "discovered current vxlan peer");
        vtep_peers.insert(destination, neighbour);
    }

    Ok(vtep_peers)
}

// TODO: pod cidrs are not strictly necessary as they are optionally set on cluster creation.
// We can have the mesh-cni-controller be in charge pod cidrs and annotate nodes (or some other
// mechanism) in the future
fn node_pod_cidrs(node: &Node) -> Result<Vec<IpNetwork>> {
    let Some(spec) = node.spec.as_ref() else {
        return Err(Error::MissingPrecondition(
            "node is missing spec".to_string(),
        ));
    };

    let cidrs = if let Some(pod_cidrs) = spec.pod_cidrs.as_ref() {
        pod_cidrs.clone()
    } else if let Some(pod_cidr) = spec.pod_cidr.as_ref() {
        vec![pod_cidr.clone()]
    } else {
        return Err(Error::MissingPrecondition(
            "node is missing cidrs in spec".to_string(),
        ));
    };

    let cidrs: Vec<IpNetwork> = cidrs
        .into_iter()
        .filter_map(|cidr| IpNetwork::from_str(&cidr).ok())
        .collect();
    if cidrs.is_empty() {
        Err(Error::MissingPrecondition(
            "no valid cidrs on node".to_string(),
        ))
    } else {
        Ok(cidrs)
    }
}

async fn upsert_node_route(ctx: &Context, cidr: IpNetwork) -> Result<()> {
    let IpNetwork::V4(cidr) = cidr else {
        return Err(Error::MissingPrecondition(
            "ipv6 route reconcile not implemented".into(),
        ));
    };

    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(cidr.ip(), cidr.prefix())
        .output_interface(ctx.mesh_vxlan_ifindex)
        .build();

    ctx.handle.route().add(route).replace().execute().await?;
    Ok(())
}

async fn remove_node_route(ctx: &Context, cidr: IpNetwork) -> Result<()> {
    let IpNetwork::V4(cidr) = cidr else {
        return Err(Error::MissingPrecondition(
            "ipv6 route reconcile not implemented".into(),
        ));
    };

    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(cidr.ip(), cidr.prefix())
        .output_interface(ctx.mesh_vxlan_ifindex)
        .build();

    ctx.handle.route().del(route).execute().await?;
    Ok(())
}

async fn upsert_vtep_peer(ctx: &Context, destination: IpAddr) -> Result<()> {
    info!(
        ifindex = ctx.mesh_vxlan_ifindex,
        %destination,
        "programming vxlan fdb peer"
    );
    ctx.handle
        .neighbours()
        .add_bridge(ctx.mesh_vxlan_ifindex, &[0, 0, 0, 0, 0, 0])
        .destination(destination)
        .flags(NeighbourFlags::Own)
        .execute()
        .await?;
    Ok(())
}

async fn remove_vtep_peer(ctx: &Context, message: NeighbourMessage) -> Result<()> {
    if let Some(destination) = neighbour_destination(&message.attributes) {
        info!(
            ifindex = ctx.mesh_vxlan_ifindex,
            %destination,
            "deleting vxlan fdb peer"
        );
    }
    ctx.handle.neighbours().del(message).execute().await?;
    Ok(())
}

fn route_output_interface(attributes: &[RouteAttribute]) -> Option<u32> {
    attributes.iter().find_map(|attr| match attr {
        RouteAttribute::Oif(index) => Some(*index),
        _ => None,
    })
}

fn route_destination(
    attributes: &[RouteAttribute],
    prefix_length: u8,
) -> Result<Option<IpNetwork>> {
    let Some(destination) = attributes.iter().find_map(|attr| match attr {
        RouteAttribute::Destination(RouteAddress::Inet(addr)) => Some(IpAddr::V4(*addr)),
        RouteAttribute::Destination(RouteAddress::Inet6(addr)) => Some(IpAddr::V6(*addr)),
        _ => None,
    }) else {
        return Ok(None);
    };

    Ok(Some(IpNetwork::new(destination, prefix_length)?))
}

fn is_zero_mac_fdb(attributes: &[NeighbourAttribute]) -> bool {
    attributes.iter().any(|attr| match attr {
        NeighbourAttribute::LinkLocalAddress(addr) => addr.as_slice() == [0, 0, 0, 0, 0, 0],
        _ => false,
    })
}

fn neighbour_destination(attributes: &[NeighbourAttribute]) -> Option<IpAddr> {
    attributes.iter().find_map(|attr| match attr {
        NeighbourAttribute::Destination(NeighbourAddress::Inet(addr)) => Some(IpAddr::V4(*addr)),
        NeighbourAttribute::Destination(NeighbourAddress::Inet6(addr)) => Some(IpAddr::V6(*addr)),
        _ => None,
    })
}

fn node_internal_ipv4(node: &Node) -> Result<Option<Ipv4Addr>> {
    let Some(status) = node.status.as_ref() else {
        return Ok(None);
    };
    let Some(addresses) = status.addresses.as_ref() else {
        return Ok(None);
    };

    addresses
        .iter()
        .find(|addr| addr.type_ == "InternalIP")
        .map(|addr| {
            Ipv4Addr::from_str(&addr.address)
                .map_err(|_| Error::InvalidAddress(addr.address.clone()))
        })
        .transpose()
}

pub(crate) fn error_policy(node: Arc<Node>, error: &Error, _ctx: Arc<Context>) -> Action {
    error!(?error, node = %node.name_any(), "node route reconcile error");
    Action::requeue(ERROR_REQUEUE_DURATION)
}
