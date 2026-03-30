use std::{collections::HashMap, net::Ipv4Addr, str::FromStr, sync::Arc, time::Duration};

use ipnetwork::IpNetwork;
use k8s_openapi::api::core::v1::Node;
use kube::{Resource, ResourceExt, runtime::controller::Action};
use mesh_cni_ebpf_common::route::RouteV4;
use tracing::{error, info, warn};

use crate::{Error, Result, VxlanRemoteCidrsDataplane, context::Context};

const DEFAULT_REQUEUE_DURATION: Duration = Duration::from_secs(300);
const ERROR_REQUEUE_DURATION: Duration = Duration::from_secs(5);

pub(crate) async fn reconcile<D>(node: Arc<Node>, ctx: Arc<Context<D>>) -> Result<Action>
where
    D: VxlanRemoteCidrsDataplane,
{
    info!(
        "started reconciling Vxlan state for Node {}",
        node.name_any()
    );
    reconcile_all_vxlan_remote_cidrs(&ctx)?;
    Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
}

pub(crate) fn reconcile_all_vxlan_remote_cidrs<D>(ctx: &Context<D>) -> Result<()>
where
    D: VxlanRemoteCidrsDataplane,
{
    let desired_remote_cidrs =
        desired_remote_cidrs(&ctx.node_store.state(), &ctx.node_name, ctx.vxlan_ifindex)?;
    let current_remote_cidrs = ctx.routes.vxlan_remote_cidrs_state()?;

    info!(
        desired_remote_cidr_count = desired_remote_cidrs.len(),
        current_remote_cidr_count = current_remote_cidrs.len(),
        "reconciling vxlan remote cidr map"
    );

    for (cidr, current_route) in &current_remote_cidrs {
        if !desired_remote_cidrs.contains_key(cidr) {
            info!(%cidr, remote_ip = %Ipv4Addr::from(current_route.remote_ip), "removing stale vxlan remote cidr");
            ctx.routes.remove_vxlan_remote_cidr(cidr)?;
        }
    }

    for (cidr, desired_route) in &desired_remote_cidrs {
        if current_remote_cidrs.get(cidr) != Some(desired_route) {
            let remote_ip = Ipv4Addr::from(desired_route.remote_ip);
            info!(%cidr, %remote_ip, "updating vxlan remote cidr");
            ctx.routes.upsert_vxlan_remote_cidr(
                *cidr,
                RouteV4::new_remote(ctx.vxlan_ifindex, remote_ip, 1),
            )?;
        }
    }

    Ok(())
}

fn desired_remote_cidrs(
    nodes: &[Arc<Node>],
    local_node_name: &str,
    vxlan_ifindex: u32,
) -> Result<HashMap<IpNetwork, RouteV4>> {
    let mut cidrs = HashMap::default();

    for node in nodes {
        if node.name_any() == local_node_name || node.meta().deletion_timestamp.is_some() {
            continue;
        }

        let Some(node_ip) = node_internal_ipv4(node)? else {
            warn!(
                node = %node.name_any(),
                "skipping vxlan remote cidr reconcile for node without IPv4 InternalIP"
            );
            continue;
        };

        let route = RouteV4::new_remote(vxlan_ifindex, node_ip, 1);
        for pod_cidr in node_pod_cidrs(node)? {
            let IpNetwork::V4(_) = pod_cidr else {
                warn!(node = %node.name_any(), cidr = %pod_cidr, "skipping non-ipv4 pod cidr");
                continue;
            };
            cidrs.insert(pod_cidr, route);
        }
    }

    Ok(cidrs)
}

// TODO: pod cidrs are not strictly necessary as they are optionally set on cluster creation.
// We can have the mesh-cni-controller be in charge pod cidrs and annotate nodes (or some other
// mechanism) in the future.
fn node_pod_cidrs(node: &Node) -> Result<Vec<IpNetwork>> {
    let Some(spec) = node.spec.as_ref() else {
        return Err(Error::MissingPrecondition(
            "node is missing spec".to_string(),
        ));
    };

    if let Some(pod_cidrs) = &spec.pod_cidrs {
        let cidrs: Vec<_> = pod_cidrs
            .iter()
            .filter_map(|cidr| IpNetwork::from_str(cidr).ok())
            .collect();
        if cidrs.is_empty() {
            return Err(Error::MissingPrecondition(
                "no valid pod cidrs found".to_string(),
            ));
        }
        Ok(cidrs)
    } else if let Some(pod_cidr) = &spec.pod_cidr {
        Ok(vec![IpNetwork::from_str(pod_cidr)?])
    } else {
        Err(Error::MissingPrecondition(
            "node is missing cidr/cidrs in spec".to_string(),
        ))
    }
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

pub(crate) fn error_policy<D>(node: Arc<Node>, error: &Error, _ctx: Arc<Context<D>>) -> Action
where
    D: VxlanRemoteCidrsDataplane,
{
    error!(?error, node = %node.name_any(), "node route reconcile error");
    Action::requeue(ERROR_REQUEUE_DURATION)
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::{NodeAddress, NodeSpec, NodeStatus};
    use kube::core::ObjectMeta;

    use super::*;

    fn node(
        name: &str,
        pod_cidrs: Option<Vec<&str>>,
        pod_cidr: Option<&str>,
        internal_ip: Option<&str>,
    ) -> Arc<Node> {
        Arc::new(Node {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: Some(NodeSpec {
                pod_cidrs: pod_cidrs.map(|cidrs| {
                    cidrs
                        .into_iter()
                        .map(std::string::ToString::to_string)
                        .collect()
                }),
                pod_cidr: pod_cidr.map(std::string::ToString::to_string),
                ..Default::default()
            }),
            status: Some(NodeStatus {
                addresses: internal_ip.map(|ip| {
                    vec![NodeAddress {
                        address: ip.to_string(),
                        type_: "InternalIP".to_string(),
                    }]
                }),
                ..Default::default()
            }),
        })
    }

    #[test]
    fn desired_remote_cidrs_skips_local_node_and_uses_remote_ipv4() {
        let nodes = vec![
            node(
                "control-plane",
                Some(vec!["10.244.0.0/24"]),
                None,
                Some("172.18.0.2"),
            ),
            node(
                "worker",
                Some(vec!["10.244.1.0/24"]),
                None,
                Some("172.18.0.6"),
            ),
        ];

        let desired = desired_remote_cidrs(&nodes, "control-plane", 1).unwrap();

        assert_eq!(desired.len(), 1);
        assert_eq!(
            desired.get(&IpNetwork::from_str("10.244.1.0/24").unwrap()),
            Some(&RouteV4::new_remote(1, Ipv4Addr::new(172, 18, 0, 6), 1))
        );
    }

    #[test]
    fn desired_remote_cidrs_skips_nodes_without_internal_ipv4() {
        let nodes = vec![
            node(
                "control-plane",
                Some(vec!["10.244.0.0/24"]),
                None,
                Some("172.18.0.2"),
            ),
            node("worker", Some(vec!["10.244.1.0/24"]), None, None),
        ];

        let desired = desired_remote_cidrs(&nodes, "control-plane", 1).unwrap();

        assert!(desired.is_empty());
    }

    #[test]
    fn node_pod_cidrs_falls_back_to_single_pod_cidr() {
        let node = Node {
            spec: Some(NodeSpec {
                pod_cidr: Some("10.244.9.0/24".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let cidrs = node_pod_cidrs(&node).unwrap();

        assert_eq!(cidrs, vec![IpNetwork::from_str("10.244.9.0/24").unwrap()]);
    }

    #[test]
    fn node_internal_ipv4_returns_invalid_address_error() {
        let node = Node {
            status: Some(NodeStatus {
                addresses: Some(vec![NodeAddress {
                    address: "not-an-ip".to_string(),
                    type_: "InternalIP".to_string(),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = node_internal_ipv4(&node).unwrap_err();

        assert!(matches!(err, Error::InvalidAddress(addr) if addr == "not-an-ip"));
    }
}
