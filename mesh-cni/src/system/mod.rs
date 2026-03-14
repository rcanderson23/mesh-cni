mod ports;
mod vxlan;

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

pub async fn ensure_vxlan(vxlan_settings: &VxlanSettings) -> Result<()> {
    vxlan::ensure_vxlan_iface(vxlan_settings).await?;
    Ok(())
}
