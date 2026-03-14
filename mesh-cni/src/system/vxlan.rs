use anyhow::bail;
use regex::Regex;
use rtnetlink::LinkVxlan;
use tokio_stream::StreamExt;

use crate::{Result, config::VxlanSettings};

pub const MESH_VXLAN_NAME: &str = "mesh_vxlan0";
pub const MESH_VXLAN_VNI: u32 = 1;
pub const MESH_VXLAN_PORT: u16 = 4789;

pub(crate) async fn ensure_vxlan_iface(settings: &VxlanSettings) -> Result<()> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);
    let iface_regex = Regex::new(&settings.iface_regex)?;
    let mut links = handle.link().get().execute();
    let mut match_index = None;
    while let Some(link) = links.try_next().await? {
        for attr in &link.attributes {
            match attr {
                rtnetlink::packet_route::link::LinkAttribute::IfName(name) => {
                    if iface_regex.is_match(name) {
                        match_index = Some(link.header.index);
                    }
                    if name == MESH_VXLAN_NAME {
                        return Ok(());
                    }
                }
                _ => continue,
            }
        }
    }
    if let Some(index) = match_index {
        let msg = LinkVxlan::new(MESH_VXLAN_NAME, MESH_VXLAN_VNI)
            .dev(index)
            .up()
            .port(MESH_VXLAN_PORT)
            .build();

        handle.link().add(msg).execute().await?;

        Ok(())
    } else {
        bail!(
            "failed to find iface matching regex {}",
            settings.iface_regex
        );
    }
}
