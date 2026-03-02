use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::anyhow;
use aya::programs::{
    SchedClassifier, TcAttachType,
    links::{FdLink, LinkError, PinnedLink},
    tc,
};
use regex::Regex;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    Result,
    bpf::{BPF_MESH_LINKS_DIR, BPF_PROGRAM_NODEPORT_EGRESS_TC, BPF_PROGRAM_NODEPORT_INGRESS_TC},
    config::NodePortSettings,
};

const HOST_NET_IFACE_DIR: &str = "/sys/class/net";
const NODEPORT_LINK_PREFIX: &str = "mesh_cni_nodeport_";
const NODEPORT_LINK_SUFFIX_INGRESS: &str = "_ingress";
const NODEPORT_LINK_SUFFIX_EGRESS: &str = "_egress";
const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

pub fn start_nodeport_iface_reconciler(
    node_port_settings: NodePortSettings,
    cancel: CancellationToken,
) -> Result<()> {
    let iface_regex = Regex::new(&node_port_settings.node_port_iface_regex).map_err(|e| {
        anyhow!(
            "invalid node port interface regex '{}': {}",
            node_port_settings.node_port_iface_regex,
            e
        )
    })?;
    info!(
        regex = %node_port_settings.node_port_iface_regex,
        "starting nodeport interface reconciler"
    );
    reconcile(&iface_regex)?;

    let mut interval = tokio::time::interval(RECONCILE_INTERVAL);

    // TODO: investigate if this can event driven using rtnetlink
    tokio::spawn(async move {
        loop {
            if let Err(err) = reconcile(&iface_regex) {
                warn!(%err, "nodeport interface reconciliation failed");
            }
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("stopping nodeport interface reconciler");
                    break;
                },
                _ = interval.tick() => {
                }
            }
        }
    });
    Ok(())
}

fn reconcile(iface_regex: &Regex) -> Result<()> {
    let desired_ifaces = get_matching_ifaces(iface_regex)?;
    let current_links = get_pinned_iface_links()?;

    for iface in &desired_ifaces {
        ensure_ipv4_accept_local_enabled(iface)?;
        ensure_nodeport_attached(iface, TcAttachType::Ingress)?;
        ensure_nodeport_attached(iface, TcAttachType::Egress)?;
    }

    for (iface, link_path) in current_links {
        if desired_ifaces.contains(&iface) {
            continue;
        }
        unpin_path(&link_path)?;
        info!(
            iface = %iface,
            path = %link_path.display(),
            "removed stale nodeport ingress link"
        );
    }

    Ok(())
}

fn ensure_ipv4_accept_local_enabled(iface: &str) -> Result<()> {
    let path = format!("/proc/sys/net/ipv4/conf/{iface}/accept_local");
    let current = fs::read_to_string(&path)?;
    if current.trim() == "1" {
        return Ok(());
    }
    fs::write(&path, b"1")?;
    info!(iface = %iface, path = %path, "enabled ipv4 accept_local for nodeport forwarding");
    Ok(())
}

fn get_matching_ifaces(iface_regex: &Regex) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(HOST_NET_IFACE_DIR)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(ToString::to_string) else {
            continue;
        };
        if iface_regex.is_match(&name) {
            names.insert(name);
        }
    }
    Ok(names)
}

fn get_pinned_iface_links() -> Result<Vec<(String, PathBuf)>> {
    let mut links = Vec::new();
    for entry in fs::read_dir(BPF_MESH_LINKS_DIR)? {
        let entry = entry?;
        let path = entry.path();
        let Some(file_name) = entry.file_name().to_str().map(ToString::to_string) else {
            continue;
        };
        let Some(iface) = iface_name_from_link_file(&file_name) else {
            continue;
        };
        links.push((iface, path));
    }
    Ok(links)
}

fn iface_name_from_link_file(file_name: &str) -> Option<String> {
    let without_prefix = file_name.strip_prefix(NODEPORT_LINK_PREFIX)?;
    let iface = without_prefix
        .strip_suffix(NODEPORT_LINK_SUFFIX_INGRESS)
        .or_else(|| without_prefix.strip_suffix(NODEPORT_LINK_SUFFIX_EGRESS))?;
    if iface.is_empty() {
        return None;
    }
    Some(iface.to_string())
}

fn ensure_nodeport_attached(iface: &str, attach_type: TcAttachType) -> Result<()> {
    let pin_path = pin_path_for_iface(iface, attach_type);
    if pin_path.try_exists()? {
        return Ok(());
    }

    let _ = tc::qdisc_add_clsact(iface);

    let prog_path = match attach_type {
        TcAttachType::Ingress => BPF_PROGRAM_NODEPORT_INGRESS_TC.path(),
        TcAttachType::Egress => BPF_PROGRAM_NODEPORT_EGRESS_TC.path(),
        TcAttachType::Custom(_) => BPF_PROGRAM_NODEPORT_INGRESS_TC.path(),
    };
    let mut prog = SchedClassifier::from_pin(prog_path)?;

    info!(iface = %iface, ?attach_type, "attaching nodeport tc program");
    let link_id = prog.attach(iface, attach_type)?;
    let link = prog.take_link(link_id)?;
    let link: FdLink = link.try_into()?;
    link.pin(pin_path)?;

    Ok(())
}

fn pin_path_for_iface(iface: &str, attach_type: TcAttachType) -> PathBuf {
    let suffix = match attach_type {
        TcAttachType::Ingress => NODEPORT_LINK_SUFFIX_INGRESS,
        TcAttachType::Egress => NODEPORT_LINK_SUFFIX_EGRESS,
        TcAttachType::Custom(_) => NODEPORT_LINK_SUFFIX_INGRESS,
    };
    PathBuf::from(BPF_MESH_LINKS_DIR).join(format!("{NODEPORT_LINK_PREFIX}{iface}{suffix}"))
}

fn unpin_path(path: impl AsRef<Path>) -> Result<()> {
    match path.as_ref().try_exists() {
        Ok(true) => {}
        Ok(false) => return Ok(()),
        Err(e) => return Err(e.into()),
    }

    match PinnedLink::from_pin(path.as_ref()) {
        Ok(link) => {
            let _link = link.unpin()?;
        }
        Err(LinkError::SyscallError(err))
            if err.io_error.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::iface_name_from_link_file;

    #[test]
    fn iface_name_from_link_file_parses_expected_name() {
        let iface = iface_name_from_link_file("mesh_cni_nodeport_eth0_ingress");
        assert_eq!(iface.as_deref(), Some("eth0"));
    }

    #[test]
    fn iface_name_from_link_file_rejects_non_matching_name() {
        let iface = iface_name_from_link_file("mesh_cni_ingress");
        assert!(iface.is_none());
    }
}
