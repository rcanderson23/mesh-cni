use std::{
    collections::{BTreeMap, BTreeSet},
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
    bpf::{BPF_MESH_LINKS_DIR, BPF_PROGRAM_NODEPORT_INGRESS_TC},
    config::NodePortSettings,
};

const HOST_NET_IFACE_DIR: &str = "/sys/class/net";
const NODEPORT_LINK_PREFIX: &str = "mesh_cni_nodeport_";
const NODEPORT_LINK_SUFFIX: &str = "_ingress";
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

    let mut interval = tokio::time::interval(RECONCILE_INTERVAL);

    tokio::spawn(async move {
        // TODO: investigate if this can event driven using rtnetlink
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
        ensure_nodeport_attached(iface)?;
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

fn get_pinned_iface_links() -> Result<BTreeMap<String, PathBuf>> {
    let mut links = BTreeMap::new();
    for entry in fs::read_dir(BPF_MESH_LINKS_DIR)? {
        let entry = entry?;
        let path = entry.path();
        let Some(file_name) = entry.file_name().to_str().map(ToString::to_string) else {
            continue;
        };
        let Some(iface) = iface_name_from_link_file(&file_name) else {
            continue;
        };
        links.insert(iface, path);
    }
    Ok(links)
}

fn iface_name_from_link_file(file_name: &str) -> Option<String> {
    let iface = file_name
        .strip_prefix(NODEPORT_LINK_PREFIX)?
        .strip_suffix(NODEPORT_LINK_SUFFIX)?;
    if iface.is_empty() {
        return None;
    }
    Some(iface.to_string())
}

fn ensure_nodeport_attached(iface: &str) -> Result<()> {
    let pin_path = pin_path_for_iface(iface);
    if pin_path.try_exists()? {
        return Ok(());
    }

    let _ = tc::qdisc_add_clsact(iface);

    let mut prog = SchedClassifier::from_pin(BPF_PROGRAM_NODEPORT_INGRESS_TC.path())?;

    info!(iface = %iface, "attaching nodeport ingress tc program");
    let link_id = prog.attach(iface, TcAttachType::Ingress)?;
    let link = prog.take_link(link_id)?;
    let link: FdLink = link.try_into()?;
    link.pin(pin_path)?;

    Ok(())
}

fn pin_path_for_iface(iface: &str) -> PathBuf {
    PathBuf::from(BPF_MESH_LINKS_DIR).join(format!(
        "{NODEPORT_LINK_PREFIX}{iface}{NODEPORT_LINK_SUFFIX}"
    ))
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
