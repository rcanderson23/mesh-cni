use std::num::NonZero;

use anyhow::bail;
use aya::programs::links::FdLink;
use aya::programs::{SchedClassifier, TcAttachType, tc};
use rtnetlink::{Error as NetlinkError, Handle, LinkDummy};
use tokio_stream::StreamExt;

use crate::Result;
use crate::bpf::{BPF_MESH_LINKS_DIR, BPF_PROGRAM_VXLAN_VETH_EGRESS_TC};

pub const MESH_ROUTER_NAME: &str = "mesh_router0";
const ROUTER_INGRESS_LINK_PREFIX: &str = "mesh_cni_router_";
const INGRESS_LINK_SUFFIX: &str = "_ingress";

pub(crate) async fn ensure_mesh_router_iface(handle: &Handle) -> Result<()> {
    ensure_dummy_router_iface(handle).await?;
    ensure_route_ebpf_attached(MESH_ROUTER_NAME)?;
    Ok(())
}

/// Ensures the dummy interface exists
async fn ensure_dummy_router_iface(handle: &Handle) -> Result<()> {
    match handle
        .link()
        .get()
        .match_name(MESH_ROUTER_NAME.to_string())
        .execute()
        .try_next()
        .await
    {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => bail!("netlink return no device on success"),
        Err(NetlinkError::NetlinkError(m))
            if m.code == Some(NonZero::new(-libc::ENODEV).unwrap()) => {}
        Err(e) => return Err(e.into()),
    }

    handle
        .link()
        .add(LinkDummy::new(MESH_ROUTER_NAME).up().build())
        .execute()
        .await?;
    Ok(())
}

fn ensure_route_ebpf_attached(iface: &str) -> Result<()> {
    let pin_path = std::path::PathBuf::from(BPF_MESH_LINKS_DIR).join(format!(
        "{ROUTER_INGRESS_LINK_PREFIX}{iface}{INGRESS_LINK_SUFFIX}"
    ));
    if pin_path.try_exists()? {
        return Ok(());
    }

    let _ = tc::qdisc_add_clsact(iface);

    let mut prog = SchedClassifier::from_pin(BPF_PROGRAM_VXLAN_VETH_EGRESS_TC.path())?;
    let link_id = prog.attach(iface, TcAttachType::Ingress)?;
    let link = prog.take_link(link_id)?;
    let link: FdLink = link.try_into()?;
    link.pin(pin_path)?;

    Ok(())
}
