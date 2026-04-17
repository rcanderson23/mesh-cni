mod nat;
mod ports;
mod router;
mod sysctl;
mod vxlan;

use anyhow::bail;
use mesh_cni_netlink::Netlink;
use regex::Regex;
use tracing::info;

use crate::{
    Result,
    config::{ProxySettings, VxlanSettings},
    system::{ports::ensure_node_ports_settings, router::MESH_ROUTER_NAME, vxlan::MESH_VXLAN_NAME},
};

const VXLAN_MTU_SUB: u32 = 50;

/// Ensures settings that are normally the responsibility of kube-proxy
pub async fn ensure_proxy_settings(settings: &ProxySettings) -> Result<()> {
    ensure_node_ports_settings(&settings.node_port_settings)?;
    Ok(())
}

pub async fn ensure_vxlan(vxlan_settings: &VxlanSettings) -> Result<u32> {
    let nl = Netlink::try_new()?;

    info!("ensuring nftables masquading");
    let regex = Regex::new(&vxlan_settings.iface_snat)?;
    let snat_iface = find_valid_snat_candidate(&nl, &regex).await?;
    nat::ensure_pod_snat(&vxlan_settings.pod_cidrs, &snat_iface)?;

    let regex = Regex::new(&vxlan_settings.iface_regex)?;
    let dev_iface = find_valid_vxlan_candidate(&nl, &regex).await?;
    let mtu = nl.get_mtu_from_iface(&dev_iface).await?;
    router::ensure_mesh_router_iface(
        &nl,
        &vxlan_settings.pod_cidrs,
        mtu.saturating_sub(VXLAN_MTU_SUB),
    )
    .await?;
    sysctl::disable_rp_filter("all")?;
    sysctl::disable_rp_filter(&dev_iface)?;

    vxlan::ensure_vxlan_iface(&nl, &dev_iface).await
}

async fn find_valid_vxlan_candidate(nl: &Netlink, regex: &Regex) -> Result<String> {
    let ifaces = nl.find_matching_ifaces(regex).await?;
    let mut candidates = Vec::new();
    for iface in ifaces {
        if iface == "lo" || iface == MESH_ROUTER_NAME || iface == MESH_VXLAN_NAME {
            continue;
        }

        let addrs = nl.get_iface_addrs(&iface).await?;
        if addrs.into_iter().any(|ip| match ip {
            std::net::IpAddr::V4(ipv4) => {
                !ipv4.is_loopback()
                    && !ipv4.is_link_local()
                    && !ipv4.is_unspecified()
                    && !ipv4.is_multicast()
            }
            std::net::IpAddr::V6(_) => false,
        }) {
            candidates.push(iface);
        };
    }

    match candidates.len() {
        0 => bail!("no valid matching iface for vxlan"),
        1 => Ok(candidates.pop().unwrap()),
        _ => bail!("found multiple matching ifaces for vxlan, narrow down regex"),
    }
}

// TODO: consolidate with vxlan candidate?
async fn find_valid_snat_candidate(nl: &Netlink, regex: &Regex) -> Result<String> {
    let ifaces = nl.find_matching_ifaces(regex).await?;
    let mut candidates = Vec::new();
    for iface in ifaces {
        if iface == "lo" || iface == MESH_ROUTER_NAME || iface == MESH_VXLAN_NAME {
            continue;
        }

        let addrs = nl.get_iface_addrs(&iface).await?;
        if addrs.into_iter().any(|ip| match ip {
            std::net::IpAddr::V4(ipv4) => {
                !ipv4.is_loopback()
                    && !ipv4.is_link_local()
                    && !ipv4.is_unspecified()
                    && !ipv4.is_multicast()
            }
            std::net::IpAddr::V6(_) => false,
        }) {
            candidates.push(iface);
        };
    }

    match candidates.len() {
        0 => bail!("no valid matching iface for snat"),
        1 => Ok(candidates.pop().unwrap()),
        _ => bail!("found multiple matching ifaces for snat, narrow down regex"),
    }
}
