use anyhow::bail;
use aya::programs::{SchedClassifier, TcAttachType, links::FdLink, tc};
use regex::Regex;
use rtnetlink::{Handle, LinkVxlan};
use tokio_stream::StreamExt;

use crate::{
    Result,
    bpf::{BPF_MESH_LINKS_DIR, BPF_PROGRAM_VXLAN_NODE_INGRESS_TC},
    config::VxlanSettings,
    system::netlink::link_index_by_name,
};

pub const MESH_VXLAN_NAME: &str = "mesh_vxlan0";
pub const MESH_VXLAN_VNI: u32 = 1;
pub const MESH_VXLAN_PORT: u16 = 4789;
const VXLAN_NODE_INGRESS_LINK_PREFIX: &str = "mesh_cni_vxlan_node_";
const INGRESS_LINK_SUFFIX: &str = "_ingress";

/// Enusres the vxlan interface is created and returns its ifindex
pub(crate) async fn ensure_vxlan_iface(handle: &Handle, settings: &VxlanSettings) -> Result<u32> {
    let iface_regex = Regex::new(&settings.iface_regex)?;
    let mut links = handle.link().get().execute();
    let mut match_index = None;
    let mut match_name = None;
    let mut vxlan_index = None;
    while let Some(link) = links.try_next().await? {
        for attr in &link.attributes {
            if let rtnetlink::packet_route::link::LinkAttribute::IfName(name) = attr {
                if iface_regex.is_match(name) {
                    match_index = Some(link.header.index);
                    match_name = Some(name.clone());
                }
                if name == MESH_VXLAN_NAME {
                    vxlan_index = Some(link.header.index);
                }
            }
        }
    }
    if let Some(vxlan_index) = vxlan_index {
        if let Some(iface_name) = match_name.as_deref() {
            ensure_vxlan_node_ingress_attached(iface_name)?;
        }
        return Ok(vxlan_index);
    }
    if let Some(index) = match_index {
        let msg = LinkVxlan::new(MESH_VXLAN_NAME, MESH_VXLAN_VNI)
            .dev(index)
            .up()
            .port(MESH_VXLAN_PORT)
            .collect_metadata(true)
            .build();

        handle.link().add(msg).execute().await?;
        let vxlan_index = link_index_by_name(handle, MESH_VXLAN_NAME).await?;
        if let Some(iface_name) = match_name.as_deref() {
            ensure_vxlan_node_ingress_attached(iface_name)?;
        }

        Ok(vxlan_index)
    } else {
        bail!(
            "failed to find iface matching regex {}",
            settings.iface_regex
        );
    }
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
