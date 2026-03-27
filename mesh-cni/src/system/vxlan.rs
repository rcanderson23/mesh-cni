use anyhow::bail;
use aya::{
    maps::{HashMap, Map, MapData},
    programs::{SchedClassifier, TcAttachType, links::FdLink, tc},
};
use mesh_cni_ebpf_common::vxlan::VXLAN_IFINDEX_SLOT;
use regex::Regex;
use rtnetlink::LinkVxlan;
use tokio_stream::StreamExt;
use tracing::info;

use crate::{
    Result,
    bpf::{BPF_MAP_IFACE_INDEXES_V4, BPF_MESH_LINKS_DIR, BPF_PROGRAM_VXLAN_NODE_INGRESS_TC},
    config::VxlanSettings,
};

pub const MESH_VXLAN_NAME: &str = "mesh_vxlan0";
pub const MESH_VXLAN_VNI: u32 = 1;
pub const MESH_VXLAN_PORT: u16 = 4789;
const VXLAN_NODE_INGRESS_LINK_PREFIX: &str = "mesh_cni_vxlan_node_";
const INGRESS_LINK_SUFFIX: &str = "_ingress";

type IfaceIndexesV4 = HashMap<MapData, u32, u32>;

pub(crate) async fn ensure_vxlan_iface(settings: &VxlanSettings) -> Result<()> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);
    let iface_regex = Regex::new(&settings.iface_regex)?;
    let mut links = handle.link().get().execute();
    let mut match_index = None;
    let mut match_name = None;
    let mut vxlan_index = None;
    while let Some(link) = links.try_next().await? {
        for attr in &link.attributes {
            match attr {
                rtnetlink::packet_route::link::LinkAttribute::IfName(name) => {
                    if iface_regex.is_match(name) {
                        match_index = Some(link.header.index);
                        match_name = Some(name.clone());
                    }
                    if name == MESH_VXLAN_NAME {
                        vxlan_index = Some(link.header.index);
                    }
                }
                _ => continue,
            }
        }
    }
    let mut map = load_iface_indexes_v4()?;
    if let Some(vxlan_index) = vxlan_index {
        map.insert(VXLAN_IFINDEX_SLOT, vxlan_index, 0)?;
        if let Some(iface_name) = match_name.as_deref() {
            ensure_vxlan_node_ingress_attached(iface_name)?;
        }
        return Ok(());
    }
    if let Some(index) = match_index {
        let msg = LinkVxlan::new(MESH_VXLAN_NAME, MESH_VXLAN_VNI)
            .dev(index)
            .up()
            .port(MESH_VXLAN_PORT)
            .collect_metadata(true)
            .build();

        handle.link().add(msg).execute().await?;
        let vxlan_index = link_index_by_name(&handle, MESH_VXLAN_NAME).await?;
        map.insert(VXLAN_IFINDEX_SLOT, vxlan_index, 0)?;
        if let Some(iface_name) = match_name.as_deref() {
            ensure_vxlan_node_ingress_attached(iface_name)?;
        }

        Ok(())
    } else {
        bail!(
            "failed to find iface matching regex {}",
            settings.iface_regex
        );
    }
}

fn load_iface_indexes_v4() -> Result<IfaceIndexesV4> {
    info!("loading v4 iface indexes map");
    let iface_indexes_v4 = MapData::from_pin(BPF_MAP_IFACE_INDEXES_V4.path())?;
    let iface_indexes_v4 = Map::HashMap(iface_indexes_v4);
    let iface_indexes_v4 = iface_indexes_v4.try_into()?;

    Ok(iface_indexes_v4)
}

async fn link_index_by_name(handle: &rtnetlink::Handle, name: &str) -> Result<u32> {
    let link = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute()
        .try_next()
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing interface {name}"))?;

    Ok(link.header.index)
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
