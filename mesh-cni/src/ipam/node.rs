use std::{net::Ipv4Addr, str::FromStr};

use ahash::HashSet;
use anyhow::{self, bail};
use cidr::Ipv4Cidr;
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::{Api, Client, api::ListParams};

use crate::{Result, ipam::v4::IpamV4};

// TODO: I believe it is possible to have multiple Pod CIDRs assigned to a node. For simplicity, we
// will start with the first Ipv4 pod network and use that and iterate/improve later.
pub async fn get_ipamv4_from_node(kube_client: Client, node_name: &str) -> Result<IpamV4> {
    let cidr = first_v4_pod_network(kube_client.clone(), node_name).await?;
    let pods: Api<Pod> = Api::all(kube_client);

    let lp = ListParams::default().fields(&format!("spec.nodeName={node_name}"));
    let list = pods.list(&lp).await?;
    let mut allocated = HashSet::default();
    list.items
        .iter()
        .filter(|p| reserve_pod(p))
        .for_each(|pod| {
            let ips = pod_v4_ips(pod);
            ips.iter().for_each(|ip| {
                if cidr.contains(ip) {
                    allocated.insert(*ip);
                }
            })
        });

    IpamV4::try_new(cidr, allocated)
}

async fn first_v4_pod_network(kube_client: Client, node_name: &str) -> Result<Ipv4Cidr> {
    let node_api: Api<Node> = Api::all(kube_client);
    let node = node_api.get(node_name).await?;
    let Some(spec) = node.spec else {
        bail!("node {node_name} missing spec");
    };
    if let Some(pod_cidrs) = spec.pod_cidrs {
        return pod_cidrs
            .iter()
            .find_map(|p| Ipv4Cidr::from_str(p).ok())
            .ok_or_else(|| anyhow::anyhow!("failed to find ipv4 on node"));
    }
    spec.pod_cidr
        .iter()
        .find_map(|p| Ipv4Cidr::from_str(p).ok())
        .ok_or_else(|| anyhow::anyhow!("failed to find ipv4 on node"))
}

fn pod_v4_ips(pod: &Pod) -> Vec<Ipv4Addr> {
    let Some(status) = &pod.status else {
        return Vec::new();
    };

    if let Some(ips) = &status.pod_ips {
        return ips
            .iter()
            .filter_map(|ip| Ipv4Addr::from_str(&ip.ip).ok())
            .collect();
    }

    status
        .pod_ip
        .as_deref()
        .and_then(|ip| Ipv4Addr::from_str(ip).ok())
        .into_iter()
        .collect()
}

fn reserve_pod(pod: &Pod) -> bool {
    matches!(
        pod.status.as_ref().and_then(|s| s.phase.as_deref()),
        Some("Running" | "Pending" | "Unknown")
    )
}
