use std::path::{Path, PathBuf};

use aya::programs::links::{FdLink, LinkError, PinnedLink};
use aya::programs::{SchedClassifier, TcAttachType, tc};
use mesh_cni_ebpf_meta::{BPF_MESH_LINKS_DIR, BPF_PROGRAM_EGRESS_TC, BPF_PROGRAM_INGRESS_TC};
use tracing::error;

use crate::MESH_LINK_PREFIX;
use crate::error::Error;

pub(crate) fn attach_pod_bpf(pod_iface: &str, container_id: &str) -> Result<(), Error> {
    let mut attached = Vec::new();

    for iface in [pod_iface, "lo"] {
        if let Err(e) = attach_for_iface(
            iface,
            container_id,
            TcAttachType::Ingress,
            TcAttachType::Egress,
        ) {
            error!(%e, "failed to attach tc programs");
            for attached_iface in attached {
                if let Err(u) = unpin_iface_paths(container_id, attached_iface) {
                    error!(%u, "failed to unpin path");
                };
            }
            return Err(e);
        }
        attached.push(iface);
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

fn pin_path(container_id: &str, iface: &str, attach_type: TcAttachType) -> PathBuf {
    let container_id = container_id.replace('/', "_");
    let iface = iface.replace('/', "_");
    let link_name = format!("{}_{}", container_id, iface);
    match attach_type {
        TcAttachType::Ingress => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{link_name}_ingress", MESH_LINK_PREFIX)),
        TcAttachType::Egress => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{link_name}_egress", MESH_LINK_PREFIX)),
        TcAttachType::Custom(_) => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{link_name}_custom", MESH_LINK_PREFIX)),
    }
}

pub(crate) fn attach_and_pin_links(
    iface: &str,
    container_id: &str,
    path: impl AsRef<Path>,
    attach_type: TcAttachType,
) -> Result<(), Error> {
    let pin_path = pin_path(container_id, iface, attach_type);
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

pub(crate) fn unpin_iface_paths(container_id: &str, iface: &str) -> Result<(), Error> {
    let ingress_path = pin_path(container_id, iface, TcAttachType::Ingress);
    let egress_path = pin_path(container_id, iface, TcAttachType::Egress);

    for path in [ingress_path, egress_path] {
        unpin_path(path)?;
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
        ingress_attach_type,
    )?;

    if let Err(e) = attach_and_pin_links(
        iface,
        container_id,
        BPF_PROGRAM_EGRESS_TC.path(),
        egress_attach_type,
    ) {
        if let Err(u) = unpin_iface_paths(container_id, iface) {
            error!(%u, "failed to unpin path");
        };
        return Err(e);
    }

    Ok(())
}
