use aya::programs::{LinkOrder, SchedClassifier, links::FdLink, tc, tc::SchedClassifierAttachment};
use ipnetwork::IpNetwork;
use mesh_cni_ebpf_meta::BPF_PROGRAM_HOST_ROUTER_EGRESS_TC;
use mesh_cni_netlink::Netlink;
use tracing::info;

use crate::{Result, bpf::BPF_MESH_LINKS_DIR};

pub const MESH_ROUTER_NAME: &str = "mesh_router0";
const ROUTER_INGRESS_LINK_PREFIX: &str = "mesh_cni_router_";
const INGRESS_LINK_SUFFIX: &str = "_ingress";

pub(crate) async fn ensure_mesh_router_iface(
    nl: &Netlink,
    routes: &[IpNetwork],
    mtu: u32,
) -> Result<()> {
    info!("ensuring {MESH_ROUTER_NAME} interface");
    let router_ifindex = nl.ensure_dummy_iface(MESH_ROUTER_NAME).await?;

    info!("attaching router bpf program");
    ensure_route_ebpf_attached(MESH_ROUTER_NAME)?;

    info!("creating host route for {MESH_ROUTER_NAME}");
    nl.ensure_route(routes, router_ifindex, mtu).await?;
    Ok(())
}

fn ensure_route_ebpf_attached(iface: &str) -> Result<()> {
    let pin_path = std::path::PathBuf::from(BPF_MESH_LINKS_DIR).join(format!(
        "{ROUTER_INGRESS_LINK_PREFIX}{iface}{INGRESS_LINK_SUFFIX}"
    ));
    if pin_path.try_exists()? {
        return Ok(());
    }

    let mut prog = SchedClassifier::from_pin(BPF_PROGRAM_HOST_ROUTER_EGRESS_TC.path())?;

    let link_id = prog.attach(
        iface,
        SchedClassifierAttachment::Tcx {
            attach_type: tc::TcxAttachType::Egress,
            link_order: LinkOrder::default(),
        },
    )?;
    let link = prog.take_link(link_id)?;
    let link: FdLink = link.try_into()?;
    link.pin(pin_path)?;

    Ok(())
}
