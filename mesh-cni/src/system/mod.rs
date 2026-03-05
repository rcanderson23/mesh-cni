mod iface;
mod ports;

use crate::{
    Result,
    config::ProxySettings,
    system::{iface::ensure_mesh_veth, ports::ensure_node_ports_settings},
};

/// Ensures settings that are normally the responsibility of kube-proxy
pub async fn ensure_proxy_settings(settings: &ProxySettings) -> Result<()> {
    ensure_mesh_veth().await?;
    ensure_node_ports_settings(&settings.node_port_settings)?;
    Ok(())
}
