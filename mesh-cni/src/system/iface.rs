use anyhow::bail;
use rtnetlink::{Handle, LinkUnspec};
use tokio_stream::StreamExt;
use tracing::info;

use crate::Result;

const MESH_HOST_INGRESS: &str = "mesh_host";
const MESH_POD_INGRESS: &str = "mesh_pod";

pub(crate) async fn ensure_mesh_veth() -> Result<()> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let mut links = handle
        .link()
        .get()
        .match_name(MESH_HOST_INGRESS.to_string())
        .execute();

    info!("checking mesh_host interface presence");
    let iface_exists = match links.try_next().await {
        Ok(msg) if msg.is_some() => true,
        Ok(_) => false,
        Err(e) if is_enodev(&e) => false,
        Err(e) => return Err(e.into()),
    };
    if !iface_exists {
        info!("creating mesh_host/mesh_pod veth");
        let add_result = handle
            .link()
            .add(rtnetlink::LinkVeth::new(MESH_HOST_INGRESS, MESH_POD_INGRESS).build())
            .execute()
            .await;
        if let Err(e) = add_result
            && !is_eexist(&e)
        {
            return Err(e.into());
        }
    }

    set_ifaces_up(handle, &[MESH_HOST_INGRESS, MESH_POD_INGRESS]).await?;
    Ok(())
}

async fn set_ifaces_up(handle: Handle, ifaces: &[&str]) -> Result<()> {
    for iface in ifaces {
        let mut links = handle.link().get().match_name(iface.to_string()).execute();
        let Some(link) = links.try_next().await? else {
            bail!("failed to find {} interface", iface);
        };
        handle
            .link()
            .set(LinkUnspec::new_with_index(link.header.index).up().build())
            .execute()
            .await?;
    }
    Ok(())
}

fn is_eexist(err: &rtnetlink::Error) -> bool {
    match err {
        rtnetlink::Error::NetlinkError(msg) => msg.to_io().raw_os_error() == Some(libc::EEXIST),
        _ => false,
    }
}

fn is_enodev(err: &rtnetlink::Error) -> bool {
    match err {
        rtnetlink::Error::NetlinkError(msg) => msg.to_io().raw_os_error() == Some(libc::ENODEV),
        _ => false,
    }
}
