use std::path::{Path, PathBuf};

use aya::programs::links::{FdLink, LinkError, PinnedLink};
use aya::programs::{SchedClassifier, TcAttachType, tc};
use mesh_cni_ebpf_meta::{
    BPF_MESH_LINKS_DIR, BPF_PROGRAM_EGRESS_TC, BPF_PROGRAM_INGRESS_TC,
    BPF_PROGRAM_VXLAN_VETH_EGRESS_TC,
};
use tracing::error;

use crate::MESH_LINK_PREFIX;
use crate::error::Error;

pub(crate) fn attach_pod_bpf(pod_iface: &str, container_id: &str) -> Result<(), Error> {
    if let Err(e) = attach_for_iface(
        pod_iface,
        container_id,
        TcAttachType::Ingress,
        TcAttachType::Egress,
    ) {
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

fn attach_type_name(attach_type: TcAttachType) -> &'static str {
    match attach_type {
        TcAttachType::Ingress => "ingress",
        TcAttachType::Egress => "egress",
        TcAttachType::Custom(_) => "custom",
    }
}

fn pin_path(
    container_id: &str,
    iface: &str,
    prog_name: &str,
    attach_type: TcAttachType,
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
    attach_type: TcAttachType,
) -> Result<(), Error> {
    let pin_path = pin_path(container_id, iface, prog_name, attach_type);
    if pin_path.try_exists()? {
        return Ok(());
    }

    let mut prog = SchedClassifier::from_pin(path)?;

    let _ = tc::qdisc_add_clsact(iface);

    let link_id = prog.attach(iface, attach_type)?;

    let link = prog.take_link(link_id)?;
    let link: FdLink = link.try_into()?;
    link.pin(pin_path)?;
    Ok(())
}

fn unpin_program_paths(container_id: &str, iface: &str, prog_name: &str) -> Result<(), Error> {
    for attach_type in [TcAttachType::Ingress, TcAttachType::Egress] {
        unpin_path(pin_path(container_id, iface, prog_name, attach_type))?;
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
        TcAttachType::Egress,
    )?;
    if let Err(e) = attach_and_pin_links(
        iface,
        container_id,
        BPF_PROGRAM_EGRESS_TC.path(),
        BPF_PROGRAM_EGRESS_TC.name(),
        TcAttachType::Ingress,
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
        TcAttachType::Ingress,
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
        (BPF_PROGRAM_INGRESS_TC.name(), TcAttachType::Egress),
        (BPF_PROGRAM_EGRESS_TC.name(), TcAttachType::Ingress),
        (
            BPF_PROGRAM_VXLAN_VETH_EGRESS_TC.name(),
            TcAttachType::Ingress,
        ),
    ] {
        unpin_path(pin_path(container_id, iface, prog_name, attach_type))?;
    }
    Ok(())
}

fn attach_for_iface(
    iface: &str,
    container_id: &str,
    ingress_attach_type: TcAttachType,
    egress_attach_type: TcAttachType,
) -> Result<(), Error> {
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
