mod nat;
mod ports;
mod router;
mod vxlan;

use anyhow::bail;
use regex::Regex;
use rtnetlink::Handle;
use tokio_stream::StreamExt;
use tracing::info;

use crate::{
    Result,
    config::{ProxySettings, VxlanSettings},
    system::ports::ensure_node_ports_settings,
};

/// Ensures settings that are normally the responsibility of kube-proxy
pub async fn ensure_proxy_settings(settings: &ProxySettings) -> Result<()> {
    ensure_node_ports_settings(&settings.node_port_settings)?;
    Ok(())
}

pub async fn ensure_vxlan(vxlan_settings: &VxlanSettings) -> Result<u32> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);
    router::ensure_mesh_router_iface(&handle).await?;
    let vxlan_ifindex = vxlan::ensure_vxlan_iface(&handle, vxlan_settings).await?;
    let iface = find_first_iface_match(&handle, &vxlan_settings.iface_snat).await?;
    info!("ensuring nftables masquading");
    nat::ensure_pod_snat(ipnetwork::IpNetwork::V4(vxlan_settings.pod_cidr), &iface)?;
    Ok(vxlan_ifindex)
}

async fn find_first_iface_match(handle: &Handle, iface_regex: &str) -> Result<String> {
    let iface_regex = Regex::new(iface_regex)?;
    let mut links = handle.link().get().execute();
    while let Some(link) = links.try_next().await? {
        for attr in &link.attributes {
            if let rtnetlink::packet_route::link::LinkAttribute::IfName(name) = attr
                && iface_regex.is_match(name)
            {
                return Ok(name.clone());
            }
        }
    }
    bail!("failed to find interface matching regex {iface_regex}")
}
