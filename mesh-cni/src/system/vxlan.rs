use aya::programs::{SchedClassifier, TcAttachType, links::FdLink, tc};
use mesh_cni_netlink::Netlink;
use regex::Regex;

use crate::{
    Result,
    bpf::{BPF_MESH_LINKS_DIR, BPF_PROGRAM_VXLAN_NODE_INGRESS_TC},
    config::VxlanSettings,
};

pub const MESH_VXLAN_NAME: &str = "mesh_vxlan0";
pub const MESH_VXLAN_VNI: u32 = 1;
pub const MESH_VXLAN_PORT: u16 = 4789;
const VXLAN_NODE_INGRESS_LINK_PREFIX: &str = "mesh_cni_vxlan_node_";
const INGRESS_LINK_SUFFIX: &str = "_ingress";

pub(crate) async fn ensure_vxlan_iface(nl: &Netlink, settings: &VxlanSettings) -> Result<u32> {
    let iface_regex = Regex::new(&settings.iface_regex)?;
    let dev_name = nl.find_first_iface_match(&iface_regex).await?;
    let dev = nl.link_index_by_name(&dev_name).await?;
    let ifindex = nl
        .ensure_vxlan_iface(MESH_VXLAN_NAME, MESH_VXLAN_VNI, MESH_VXLAN_PORT, dev)
        .await?;
    ensure_vxlan_node_ingress_attached(&dev_name)?;

    Ok(ifindex)
}
fn ensure_vxlan_node_ingress_attached(iface: &str) -> Result<()> {
    let pin_path = std::path::PathBuf::from(BPF_MESH_LINKS_DIR).join(format!(
        "{VXLAN_NODE_INGRESS_LINK_PREFIX}{iface}{INGRESS_LINK_SUFFIX}"
    ));
    if pin_path.try_exists()? {
        return Ok(());
    }

    let _ = tc::qdisc_add_clsact(iface);

    let mut prog = SchedClassifier::from_pin(BPF_PROGRAM_VXLAN_NODE_INGRESS_TC.path())?;
    let link_id = prog.attach(iface, TcAttachType::Ingress)?;
    let link = prog.take_link(link_id)?;
    let link: FdLink = link.try_into()?;
    link.pin(pin_path)?;

    Ok(())
}
