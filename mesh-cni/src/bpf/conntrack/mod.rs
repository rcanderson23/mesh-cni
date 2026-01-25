pub mod api;

use std::time::Duration;

use aya::maps::{HashMap, Map, MapData};
use mesh_cni_api::conntrack::v1::conntrack_server::ConntrackServer;
use mesh_cni_ebpf_common::conntrack::{ConntrackKeyV4, ConntrackValue};
use nix::time::{ClockId, clock_gettime};
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{
    Result,
    bpf::{BPF_MAP_CONNTRACK_V4, conntrack::api::Conntrack},
};

const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);
const CT_TIMEOUT_TCP_NS: u64 = 60 * 60 * 12 * 1_000_000_000;
const CT_TIMEOUT_UDP_NS: u64 = 60 * 1_000_000_000;

pub async fn run(cancel: CancellationToken) -> Result<ConntrackServer<Conntrack>> {
    info!("starting bpf conntrack cleanup task");
    tokio::spawn(run_cleanup(cancel.child_token()));

    let state = api::Conntrack;
    let server = ConntrackServer::new(state);

    Ok(server)
}

pub async fn run_cleanup(cancel: CancellationToken) -> Result<()> {
    let mut map = load_map()?;
    let mut ticker = interval(CLEANUP_INTERVAL);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                if let Err(e) = cleanup_map(&mut map) {
                    error!(%e, "error cleaning up conntrack");
                };
            }
        }
    }

    Ok(())
}

pub(crate) fn load_map() -> Result<HashMap<MapData, ConntrackKeyV4, ConntrackValue>> {
    let map = MapData::from_pin(BPF_MAP_CONNTRACK_V4.path())?;
    let map = Map::LruHashMap(map);
    let map = map.try_into()?;
    Ok(map)
}

fn cleanup_map(map: &mut HashMap<MapData, ConntrackKeyV4, ConntrackValue>) -> Result<()> {
    let now = monotonic_ns()?;
    let mut expired = Vec::new();

    for entry in map.iter() {
        let (key, value) = entry?;
        // TODO: re-examine these for more appropriate values
        let timeout = match key.proto {
            1 => CT_TIMEOUT_UDP_NS,
            6 => CT_TIMEOUT_TCP_NS,
            17 => CT_TIMEOUT_UDP_NS,
            58 => CT_TIMEOUT_UDP_NS,
            132 => CT_TIMEOUT_UDP_NS,
            _ => CT_TIMEOUT_UDP_NS,
        };
        if now.saturating_sub(value.last_seen_ns) > timeout {
            expired.push(key);
        }
    }

    for key in expired {
        map.remove(&key)?;
    }

    Ok(())
}

fn monotonic_ns() -> Result<u64> {
    let ts = clock_gettime(ClockId::CLOCK_MONOTONIC)?;
    Ok((ts.tv_sec() as u64).saturating_mul(1_000_000_000) + ts.tv_nsec() as u64)
}
