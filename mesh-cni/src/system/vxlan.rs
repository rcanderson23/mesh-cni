use aya::programs::{
    LinkOrder, SchedClassifier,
    links::FdLink,
    tc::{self, SchedClassifierAttachment},
};
use mesh_cni_netlink::Netlink;

use crate::{
    Result,
    bpf::{BPF_MESH_LINKS_DIR, BPF_PROGRAM_VXLAN_NODE_INGRESS_TC},
};

pub const MESH_VXLAN_NAME: &str = "mesh_vxlan0";
pub const MESH_VXLAN_VNI: u32 = 1;
pub const MESH_VXLAN_PORT: u16 = 4789;
const VXLAN_NODE_INGRESS_LINK_PREFIX: &str = "mesh_cni_vxlan_node_";
const INGRESS_LINK_SUFFIX: &str = "_ingress";

pub(crate) async fn ensure_vxlan_iface(nl: &Netlink, dev_iface: &str) -> Result<u32> {
    let dev = nl.get_link_index_by_name(dev_iface).await?;
    let ifindex = nl
        .ensure_vxlan_iface(MESH_VXLAN_NAME, MESH_VXLAN_VNI, MESH_VXLAN_PORT, dev)
        .await?;
    ensure_vxlan_node_ingress_attached(dev_iface)?;

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
    let link_id = prog.attach(
        iface,
        SchedClassifierAttachment::Tcx {
            attach_type: tc::TcxAttachType::Ingress,
            link_order: LinkOrder::default(),
        },
    )?;
    let link = prog.take_link(link_id)?;
    let link: FdLink = link.try_into()?;
    link.pin(pin_path)?;

    Ok(())
}
