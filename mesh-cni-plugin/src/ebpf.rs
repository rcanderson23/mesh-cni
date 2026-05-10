use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use aya::{
    maps::{HashMap, Map, MapData, MapError},
    programs::{
        LinkOrder, SchedClassifier, TcxAttachType,
        links::{FdLink, LinkError, PinnedLink},
        tc::{NetkitAttachType, SchedClassifierAttachment},
    },
};
use mesh_cni_ebpf_meta::{
    BPF_MAP_IFINDEX_V4, BPF_MESH_LINKS_DIR, BPF_PROGRAM_EGRESS_TC, BPF_PROGRAM_INGRESS_TC,
    BPF_PROGRAM_VXLAN_VETH_EGRESS_TC,
};
use tracing::error;

use crate::{MESH_LINK_PREFIX, error::Error};

pub(crate) fn attach_pod_bpf(pod_iface: &str, container_id: &str) -> Result<(), Error> {
    if let Err(e) = attach_for_iface(pod_iface, container_id) {
        error!(%e, "failed to attach tc programs");
        if let Err(u) = unpin_iface_paths(container_id, pod_iface) {
            error!(%u, "failed to unpin path");
        };
        return Err(e);
    }

    Ok(())
}

fn unpin_path(path: impl AsRef<Path>) -> Result<(), Error> {
    match path.as_ref().try_exists() {
        Ok(true) => {}
        Ok(false) => return Ok(()),
        Err(e) => {
            return Err(e.into());
        }
    }
    match PinnedLink::from_pin(path) {
        Ok(link) => {
            let _link = link.unpin()?;
        }
        Err(LinkError::SyscallError(err))
            if err.io_error.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn attach_type_name(attach_type: &SchedClassifierAttachment) -> &'static str {
    match attach_type {
        SchedClassifierAttachment::Tc {
            attach_type,
            options: _,
        } => match attach_type {
            aya::programs::TcAttachType::Ingress => "ingress",
            aya::programs::TcAttachType::Egress => "egress",
            aya::programs::TcAttachType::Custom(_) => "custom",
        },
        SchedClassifierAttachment::Tcx {
            attach_type,
            link_order: _,
        } => match attach_type {
            aya::programs::TcxAttachType::Ingress => "ingress",
            aya::programs::TcxAttachType::Egress => "egress",
        },
        SchedClassifierAttachment::Netkit {
            attach_type,
            link_order: _,
        } => match attach_type {
            NetkitAttachType::Primary => "primary",
            NetkitAttachType::Peer => "peer",
        },
    }
}

fn pin_path(
    container_id: &str,
    iface: &str,
    prog_name: &str,
    attach_type: &SchedClassifierAttachment,
) -> PathBuf {
    let attach_type = attach_type_name(attach_type);

    PathBuf::from(BPF_MESH_LINKS_DIR).join(format!(
        "{MESH_LINK_PREFIX}{container_id}_{iface}_{prog_name}_{attach_type}"
    ))
}

pub(crate) fn attach_and_pin_links(
    iface: &str,
    container_id: &str,
    path: impl AsRef<Path>,
    prog_name: &str,
    attach_type: SchedClassifierAttachment,
) -> Result<(), Error> {
    let pin_path = pin_path(container_id, iface, prog_name, &attach_type);
    if pin_path.try_exists()? {
        return Ok(());
    }

    let mut prog = SchedClassifier::from_pin(path)?;

    let link_id = prog.attach(iface, attach_type)?;

    let link = prog.take_link(link_id)?;
    let link: FdLink = link.try_into()?;
    link.pin(pin_path)?;
    Ok(())
}

fn unpin_program_paths(container_id: &str, iface: &str, prog_name: &str) -> Result<(), Error> {
    for attach_type in [
        SchedClassifierAttachment::Netkit {
            attach_type: NetkitAttachType::Primary,
            link_order: LinkOrder::default(),
        },
        SchedClassifierAttachment::Netkit {
            attach_type: NetkitAttachType::Peer,
            link_order: LinkOrder::default(),
        },
        SchedClassifierAttachment::Tcx {
            attach_type: TcxAttachType::Ingress,
            link_order: LinkOrder::default(),
        },
        SchedClassifierAttachment::Tcx {
            attach_type: TcxAttachType::Egress,
            link_order: LinkOrder::default(),
        },
    ] {
        unpin_path(pin_path(container_id, iface, prog_name, &attach_type))?;
    }
    Ok(())
}

pub(crate) fn unpin_iface_paths(container_id: &str, iface: &str) -> Result<(), Error> {
    for prog_name in [BPF_PROGRAM_INGRESS_TC.name(), BPF_PROGRAM_EGRESS_TC.name()] {
        unpin_program_paths(container_id, iface, prog_name)?;
    }
    Ok(())
}

pub(crate) fn attach_host_netkit_bpf(iface: &str, container_id: &str) -> Result<(), Error> {
    attach_and_pin_links(
        iface,
        container_id,
        BPF_PROGRAM_INGRESS_TC.path(),
        BPF_PROGRAM_INGRESS_TC.name(),
        SchedClassifierAttachment::Netkit {
            attach_type: NetkitAttachType::Primary,
            link_order: LinkOrder::default(),
        },
    )?;
    if let Err(e) = attach_and_pin_links(
        iface,
        container_id,
        BPF_PROGRAM_EGRESS_TC.path(),
        BPF_PROGRAM_EGRESS_TC.name(),
        SchedClassifierAttachment::Netkit {
            attach_type: NetkitAttachType::Peer,
            link_order: LinkOrder::default(),
        },
    ) {
        if let Err(u) = unpin_host_netkit_bpf(iface, container_id) {
            error!(%u, "failed to unpin host netkit path");
        }
        return Err(e);
    }
    if let Err(e) = attach_and_pin_links(
        iface,
        container_id,
        BPF_PROGRAM_VXLAN_VETH_EGRESS_TC.path(),
        BPF_PROGRAM_VXLAN_VETH_EGRESS_TC.name(),
        SchedClassifierAttachment::Netkit {
            attach_type: NetkitAttachType::Peer,
            link_order: LinkOrder::default(),
        },
    ) {
        if let Err(u) = unpin_host_netkit_bpf(iface, container_id) {
            error!(%u, "failed to unpin host netkit path");
        }
        return Err(e);
    }

    Ok(())
}

pub(crate) fn unpin_host_netkit_bpf(iface: &str, container_id: &str) -> Result<(), Error> {
    for (prog_name, attach_type) in [
        (
            BPF_PROGRAM_INGRESS_TC.name(),
            SchedClassifierAttachment::Netkit {
                attach_type: NetkitAttachType::Primary,
                link_order: LinkOrder::default(),
            },
        ),
        (
            BPF_PROGRAM_EGRESS_TC.name(),
            SchedClassifierAttachment::Netkit {
                attach_type: NetkitAttachType::Peer,
                link_order: LinkOrder::default(),
            },
        ),
        (
            BPF_PROGRAM_VXLAN_VETH_EGRESS_TC.name(),
            SchedClassifierAttachment::Netkit {
                attach_type: NetkitAttachType::Peer,
                link_order: LinkOrder::default(),
            },
        ),
    ] {
        unpin_path(pin_path(container_id, iface, prog_name, &attach_type))?;
    }
    Ok(())
}

fn attach_for_iface(iface: &str, container_id: &str) -> Result<(), Error> {
    let ingress_attach_type = SchedClassifierAttachment::Tcx {
        attach_type: aya::programs::TcxAttachType::Ingress,
        link_order: LinkOrder::default(),
    };
    let egress_attach_type = SchedClassifierAttachment::Tcx {
        attach_type: aya::programs::TcxAttachType::Egress,
        link_order: LinkOrder::default(),
    };
    attach_and_pin_links(
        iface,
        container_id,
        BPF_PROGRAM_INGRESS_TC.path(),
        BPF_PROGRAM_INGRESS_TC.name(),
        ingress_attach_type,
    )?;

    if let Err(e) = attach_and_pin_links(
        iface,
        container_id,
        BPF_PROGRAM_EGRESS_TC.path(),
        BPF_PROGRAM_EGRESS_TC.name(),
        egress_attach_type,
    ) {
        if let Err(u) = unpin_iface_paths(container_id, iface) {
            error!(%u, "failed to unpin path");
        };
        return Err(e);
    }

    Ok(())
}

pub(crate) fn upsert_ifindex_v4_map(addr: Ipv4Addr, ifindex: u32) -> Result<(), Error> {
    let mut ifindex_v4_map = load_ifindex_v4_map()?;
    ifindex_v4_map
        .insert(addr.to_bits(), ifindex, 0)
        .map_err(|e| Error::Ebpf(e.to_string()))?;
    Ok(())
}

pub(crate) fn delete_ifindex_v4_map(addr: Ipv4Addr) -> Result<(), Error> {
    let mut ifindex_v4_map = load_ifindex_v4_map()?;
    if let Err(e) = ifindex_v4_map.remove(&addr.to_bits())
        && !matches!(e, aya::maps::MapError::KeyNotFound)
    {
        return Err(Error::Ebpf(e.to_string()));
    }
    Ok(())
}

fn load_ifindex_v4_map() -> Result<HashMap<MapData, u32, u32>, Error> {
    let ifindex_v4_map = MapData::from_pin(BPF_MAP_IFINDEX_V4.path())
        .map_err(|e| Error::Ebpf(format!("failed to load map data from pin: {}", e)))?;
    let ifindex_v4_map = Map::HashMap(ifindex_v4_map);

    let ifindex_v4_map: HashMap<MapData, u32, u32> = ifindex_v4_map
        .try_into()
        .map_err(|e: MapError| Error::Ebpf(format!("failed to convert in hashmap: {}", e)))?;
    Ok(ifindex_v4_map)
}
