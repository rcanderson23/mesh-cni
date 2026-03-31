use std::{net::Ipv4Addr, num::NonZero};

use aya::programs::{SchedClassifier, TcAttachType, links::FdLink, tc};
use ipnetwork::IpNetwork;
use rtnetlink::{
    Error as NetlinkError, Handle, LinkDummy, RouteMessageBuilder, packet_route::route::RouteMetric,
};
use tokio_stream::StreamExt;
use tracing::{info, warn};

use crate::{
    Result,
    bpf::{BPF_MESH_LINKS_DIR, BPF_PROGRAM_VXLAN_VETH_EGRESS_TC},
    system::netlink::link_index_by_name,
};

pub const MESH_ROUTER_NAME: &str = "mesh_router0";
const ROUTER_INGRESS_LINK_PREFIX: &str = "mesh_cni_router_";
const INGRESS_LINK_SUFFIX: &str = "_ingress";

pub(crate) async fn ensure_mesh_router_iface(
    handle: &Handle,
    routes: &[IpNetwork],
    mtu: u32,
) -> Result<()> {
    info!("ensuring {MESH_ROUTER_NAME} interface");
    let router_ifindex = ensure_dummy_router_iface(handle).await?;

    info!("attaching router bpf program");
    ensure_route_ebpf_attached(MESH_ROUTER_NAME)?;

    info!("creating host route for {MESH_ROUTER_NAME}");
    ensure_routes_to_mesh_router(handle, routes, router_ifindex, mtu).await?;
    Ok(())
}

/// Ensures the dummy interface exists
async fn ensure_dummy_router_iface(handle: &Handle) -> Result<u32> {
    match handle
        .link()
        .get()
        .match_name(MESH_ROUTER_NAME.to_string())
        .execute()
        .try_next()
        .await
    {
        Ok(Some(l)) => {
            return Ok(l.header.index);
        }
        // attempt to create here although I don't know the circumstances where
        // this will happen as it appears we get an error if we try to fetch an interface that
        // doesn't exist
        Ok(None) => {}
        Err(NetlinkError::NetlinkError(m))
            if m.code == Some(NonZero::new(-libc::ENODEV).unwrap()) => {}
        Err(e) => return Err(e.into()),
    }

    handle
        .link()
        .add(LinkDummy::new(MESH_ROUTER_NAME).up().build())
        .execute()
        .await?;

    link_index_by_name(handle, MESH_ROUTER_NAME).await
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
    let link_id = prog.attach(iface, TcAttachType::Egress)?;
    let link = prog.take_link(link_id)?;
    let link: FdLink = link.try_into()?;
    link.pin(pin_path)?;

    Ok(())
}

async fn ensure_routes_to_mesh_router(
    handle: &Handle,
    routes: &[IpNetwork],
    router_ifindex: u32,
    mtu: u32,
) -> Result<()> {
    for route in routes {
        match route {
            IpNetwork::V4(network) => {
                let mut msg = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(network.ip(), network.prefix())
                    .output_interface(router_ifindex)
                    .build();

                msg.attributes
                    .push(rtnetlink::packet_route::route::RouteAttribute::Metrics(
                        vec![RouteMetric::Mtu(mtu)],
                    ));
                handle.route().add(msg).replace().execute().await?;
            }
            IpNetwork::V6(_) => {
                warn!("ipv6 routes to mesh router are not implemented");
            }
        }
    }

    Ok(())
}
