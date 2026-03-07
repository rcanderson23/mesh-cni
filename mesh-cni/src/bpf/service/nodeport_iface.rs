use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::anyhow;
use aya::{
    maps::{Array, HashMap as AyaHashMap, Map, MapData},
    programs::{
        SchedClassifier, TcAttachType,
        links::{FdLink, LinkError, PinnedLink},
        tc,
    },
};
use regex::Regex;
use rtnetlink::{Handle, packet_route::address::AddressAttribute};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    Result,
    bpf::{
        BPF_MAP_NODEPORT_IFACE_INDEXES, BPF_MAP_NODEPORT_LOCAL_ADDRS_V4, BPF_MESH_LINKS_DIR,
        BPF_PROGRAM_NODEPORT_INGRESS_TC,
    },
    config::NodePortSettings,
};

const HOST_NET_IFACE_DIR: &str = "/sys/class/net";
const HOST_IFACE_INDEX_FILE: &str = "ifindex";
const MESH_HOST_IFACE: &str = "mesh_host";
const MESH_POD_IFACE: &str = "mesh_pod";
const MESH_HOST_IFACE_KEY: u32 = 0;
const MESH_POD_IFACE_KEY: u32 = 1;
const NODEPORT_LINK_PREFIX: &str = "mesh_cni_nodeport_";
const NODEPORT_LINK_SUFFIX: &str = "_ingress";
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

    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    reconcile(&iface_regex, &handle).await?;

    let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
    let handle = handle.clone();

    tokio::spawn(async move {
        interval.tick().await;
        // TODO: investigate if this can event driven using rtnetlink
        loop {
            if let Err(err) = reconcile(&iface_regex, &handle).await {
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

async fn reconcile(iface_regex: &Regex, handle: &Handle) -> Result<()> {
    // in case mesh owned interfaces are deleted and get recreated
    // we need to update the map with new values
    reconcile_mesh_iface_indexes()?;

    let desired_ifaces = get_matching_ifaces(iface_regex)?;
    reconcile_local_addrs_v4(&desired_ifaces, handle).await?;
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
            %iface,
            path = %link_path.display(),
            "removed stale nodeport ingress link"
        );
    }

    Ok(())
}

async fn reconcile_local_addrs_v4(
    desired_ifaces: &BTreeSet<String>,
    handle: &Handle,
) -> Result<()> {
    let desired_addrs = local_addrs_v4_for_ifaces(desired_ifaces, handle).await?;
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

fn reconcile_mesh_iface_indexes() -> Result<()> {
    let mut iface_indexes = load_nodeport_iface_indexes()?;
    let mesh_host_ifindex = iface_index(MESH_HOST_IFACE)?;
    let mesh_pod_ifindex = iface_index(MESH_POD_IFACE)?;
    iface_indexes.set(MESH_HOST_IFACE_KEY, mesh_host_ifindex, 0)?;
    iface_indexes.set(MESH_POD_IFACE_KEY, mesh_pod_ifindex, 0)?;
    Ok(())
}

fn load_nodeport_iface_indexes() -> Result<Array<MapData, u32>> {
    let map = MapData::from_pin(BPF_MAP_NODEPORT_IFACE_INDEXES.path())?;
    let map = Map::Array(map);
    let map = map.try_into()?;
    Ok(map)
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
    handle: &Handle,
) -> Result<BTreeSet<u32>> {
    let mut addrs = BTreeSet::new();
    for iface in desired_ifaces {
        let mut links = handle
            .clone()
            .link()
            .get()
            .match_name(iface.clone())
            .execute();
        let Some(link) = links.try_next().await? else {
            warn!(%iface, "failed to find interface while reconciling nodeport local addrs");
            continue;
        };
        let mut addresses = handle
            .clone()
            .address()
            .get()
            .set_link_index_filter(link.header.index)
            .execute();
        while let Some(msg) = addresses.try_next().await? {
            for attr in msg.attributes {
                if let AddressAttribute::Local(IpAddr::V4(ip)) = attr {
                    addrs.insert(u32::from(ip));
                }
            }
        }
    }
    Ok(addrs)
}

fn iface_index(iface: &str) -> Result<u32> {
    let path = PathBuf::from(HOST_NET_IFACE_DIR)
        .join(iface)
        .join(HOST_IFACE_INDEX_FILE);
    let ifindex = fs::read_to_string(&path)?;
    let ifindex = ifindex
        .trim()
        .parse::<u32>()
        .map_err(|e| anyhow!("invalid ifindex for {} at {}: {}", iface, path.display(), e))?;
    Ok(ifindex)
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

    info!(%iface, "attaching nodeport ingress tc program");
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
