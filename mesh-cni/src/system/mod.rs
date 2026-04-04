mod nat;
mod ports;
mod router;
mod sysctl;
mod vxlan;

use mesh_cni_netlink::Netlink;
use regex::Regex;
use tracing::info;

use crate::{
    Result,
    config::{ProxySettings, VxlanSettings},
    system::ports::ensure_node_ports_settings,
};

const VXLAN_MTU_SUB: u32 = 50;

/// Ensures settings that are normally the responsibility of kube-proxy
pub async fn ensure_proxy_settings(settings: &ProxySettings) -> Result<()> {
    ensure_node_ports_settings(&settings.node_port_settings)?;
    Ok(())
}

// FIXME: the iface selection is buggy in multi-nic environments. Make a more deterministic choice
pub async fn ensure_vxlan(vxlan_settings: &VxlanSettings) -> Result<u32> {
    let nl = Netlink::try_new()?;
    info!("getting MTU from host interface");
    let regex = Regex::new(&vxlan_settings.iface_regex)?;
    let vxlan_iface = nl.find_first_iface_match(&regex).await?;
    let mtu = nl.get_mtu_from_iface(&vxlan_iface).await?;
    router::ensure_mesh_router_iface(
        &nl,
        &vxlan_settings.pod_cidrs,
        mtu.saturating_sub(VXLAN_MTU_SUB),
    )
    .await?;
    let vxlan_ifindex = vxlan::ensure_vxlan_iface(&nl, vxlan_settings).await?;
    info!("ensuring nftables masquading");
    let regex = Regex::new(&vxlan_settings.iface_snat)?;
    let iface = nl.find_first_iface_match(&regex).await?;
    nat::ensure_pod_snat(&vxlan_settings.pod_cidrs, &iface)?;
    sysctl::disable_rp_filter("all")?;
    sysctl::disable_rp_filter(&vxlan_iface)?;
    Ok(vxlan_ifindex)
}
