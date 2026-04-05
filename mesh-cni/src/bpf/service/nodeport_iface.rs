use std::{
    collections::BTreeSet,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::anyhow;
use aya::{
    maps::{HashMap as AyaHashMap, Map, MapData},
    programs::{
        SchedClassifier, TcAttachType,
        links::{FdLink, LinkError, PinnedLink},
        tc,
    },
};
use mesh_cni_netlink::Netlink;
use regex::Regex;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    Result,
    bpf::{
        BPF_MAP_NODEPORT_LOCAL_ADDRS_V4, BPF_MESH_LINKS_DIR, BPF_PROGRAM_NODEPORT_EGRESS_TC,
        BPF_PROGRAM_NODEPORT_INGRESS_TC, BpfNamePath,
    },
    config::NodePortSettings,
};

const HOST_NET_IFACE_DIR: &str = "/sys/class/net";
const INGRESS_LINK_SUFFIX: &str = "_ingress";
const EGRESS_LINK_SUFFIX: &str = "_egress";
const NODEPORT_LINK_PREFIX: &str = "mesh_cni_nodeport_";
const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

pub async fn start_nodeport_iface_reconciler(
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

    let nl = Netlink::try_new()?;

    reconcile(&iface_regex, &nl).await?;

    let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
    let nl = nl.clone();

    tokio::spawn(async move {
        interval.tick().await;
        // TODO: investigate if this can event driven using rtnetlink
        loop {
            if let Err(err) = reconcile(&iface_regex, &nl).await {
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

async fn reconcile(iface_regex: &Regex, nl: &Netlink) -> Result<()> {
    let desired_ifaces = get_matching_ifaces(iface_regex)?;
    reconcile_local_addrs_v4(&desired_ifaces, nl).await?;
    let current_links = get_pinned_iface_links()?;

    for iface in &desired_ifaces {
        info!(%iface, "attaching ingress hook to nodeport interface");
        ensure_tc_attached(
            iface,
            BPF_PROGRAM_NODEPORT_INGRESS_TC,
            NODEPORT_LINK_PREFIX,
            TcAttachType::Ingress,
        )?;
        info!(%iface, "attaching egress hook to nodeport interface");
        ensure_tc_attached(
            iface,
            BPF_PROGRAM_NODEPORT_EGRESS_TC,
            NODEPORT_LINK_PREFIX,
            TcAttachType::Egress,
        )?;
    }

    for (iface, link_path) in current_links {
        if desired_ifaces.contains(&iface) {
            continue;
        }
        unpin_path(&link_path)?;
        info!(
            %iface,
            path = %link_path.display(),
            "removed stale nodeport tc link"
        );
    }

    Ok(())
}

async fn reconcile_local_addrs_v4(desired_ifaces: &BTreeSet<String>, nl: &Netlink) -> Result<()> {
    let desired_addrs = local_addrs_v4_for_ifaces(desired_ifaces, nl).await?;
    let mut local_addrs_map = load_nodeport_local_addrs_map()?;
    let current_addrs = local_addrs_v4_from_map(&local_addrs_map)?;

    for stale_ip in current_addrs.difference(&desired_addrs) {
        local_addrs_map.remove(stale_ip)?;
    }
    for local_ip in desired_addrs.difference(&current_addrs) {
        local_addrs_map.insert(*local_ip, 1, 0)?;
    }

    Ok(())
}

fn load_nodeport_local_addrs_map() -> Result<AyaHashMap<MapData, u32, u8>> {
    let map = MapData::from_pin(BPF_MAP_NODEPORT_LOCAL_ADDRS_V4.path())?;
    let map = Map::HashMap(map);
    let map = map.try_into()?;
    Ok(map)
}

fn local_addrs_v4_from_map(map: &AyaHashMap<MapData, u32, u8>) -> Result<BTreeSet<u32>> {
    let mut addrs = BTreeSet::new();
    for entry in map.iter() {
        let (ip, _) = entry?;
        addrs.insert(ip);
    }
    Ok(addrs)
}

async fn local_addrs_v4_for_ifaces(
    desired_ifaces: &BTreeSet<String>,
    nl: &Netlink,
) -> Result<BTreeSet<u32>> {
    let mut addrs = BTreeSet::new();
    for iface in desired_ifaces {
        let Ok(ifindex) = nl.get_link_index_by_name(iface).await else {
            warn!(%iface, "failed to find interface while reconciling nodeport local addrs");
            continue;
        };

        let iface_addrs = nl.get_addrs_from_iface(ifindex).await?;
        for addr in iface_addrs {
            // TODO: support ipv6
            if let IpAddr::V4(ipv4) = addr {
                addrs.insert(u32::from(ipv4));
            }
        }
    }
    Ok(addrs)
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
    let name = file_name.strip_prefix(NODEPORT_LINK_PREFIX)?;
    let iface = name
        .strip_suffix(INGRESS_LINK_SUFFIX)
        .or_else(|| name.strip_suffix(EGRESS_LINK_SUFFIX))?;
    if iface.is_empty() {
        return None;
    }
    Some(iface.to_string())
}

fn ensure_tc_attached(
    iface: &str,
    prog: BpfNamePath,
    prefix: &str,
    attach_type: TcAttachType,
) -> Result<()> {
    let suffix = match attach_type {
        TcAttachType::Ingress => INGRESS_LINK_SUFFIX,
        TcAttachType::Egress => EGRESS_LINK_SUFFIX,
        TcAttachType::Custom(_) => unreachable!(),
    };
    let pin_path = pin_path_for_iface(iface, prefix, suffix);
    if pin_path.try_exists()? {
        return Ok(());
    }

    let _ = tc::qdisc_add_clsact(iface);

    let mut prog = SchedClassifier::from_pin(prog.path())?;

    info!(%iface, "attaching tc program");
    let link_id = prog.attach(iface, attach_type)?;
    let link = prog.take_link(link_id)?;
    let link: FdLink = link.try_into()?;
    link.pin(pin_path)?;

    Ok(())
}

fn pin_path_for_iface(iface: &str, prefix: &str, suffix: &str) -> PathBuf {
    PathBuf::from(BPF_MESH_LINKS_DIR).join(format!("{prefix}{iface}{suffix}"))
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
    fn iface_name_from_link_file_parses_expected_name_ingress() {
        let iface = iface_name_from_link_file("mesh_cni_nodeport_eth0_ingress");
        assert_eq!(iface.as_deref(), Some("eth0"));
    }

    #[test]
    fn iface_name_from_link_file_parses_expected_name_egress() {
        let iface = iface_name_from_link_file("mesh_cni_nodeport_eth0_egress");
        assert_eq!(iface.as_deref(), Some("eth0"));
    }

    #[test]
    fn iface_name_from_link_file_rejects_non_matching_name() {
        let iface = iface_name_from_link_file("mesh_cni_ingress");
        assert!(iface.is_none());
    }
}
