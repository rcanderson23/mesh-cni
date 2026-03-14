use std::time::Duration;

use aya::maps::{HashMap, Map, MapData};
use mesh_cni_ebpf_common::conntrack::{
    CT_TIMEOUT_TCP_ESTABLISHED_NS, CT_TIMEOUT_TCP_FIN_NS, CT_TIMEOUT_TCP_RST_NS,
    CT_TIMEOUT_TCP_SYN_NS, CT_TIMEOUT_UDP_NS, ConntrackKeyV4, ConntrackValue,
    NodePortConntrackV4Key, NodePortConntrackV4Value, TcpState,
};
use mesh_cni_ebpf_common::service::{NodePortRevNatV4Key, NodePortRevNatV4Value};
use nix::time::{ClockId, clock_gettime};
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{
    Result,
    bpf::{BPF_MAP_CONNTRACK_V4, BPF_MAP_NODEPORT_CONNTRACK_V4, BPF_MAP_NODEPORT_REV_NAT_V4},
};

const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

pub async fn run_cleanup(cancel: CancellationToken) -> Result<()> {
    info!("starting bpf conntrack cleanup task");
    let mut map = load_map()?;
    let mut nodeport_map = load_nodeport_map()?;
    let mut nodeport_rev_nat_map = load_nodeport_rev_nat_map()?;
    let mut ticker = interval(CLEANUP_INTERVAL);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                if let Err(e) = cleanup_map(&mut map) {
                    error!(%e, "error cleaning up conntrack");
                };
                if let Err(e) = cleanup_nodeport_map(&mut nodeport_map, &mut nodeport_rev_nat_map) {
                    error!(%e, "error cleaning up nodeport conntrack");
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

pub(crate) fn load_nodeport_map()
-> Result<HashMap<MapData, NodePortConntrackV4Key, NodePortConntrackV4Value>> {
    let map = MapData::from_pin(BPF_MAP_NODEPORT_CONNTRACK_V4.path())?;
    let map = Map::LruHashMap(map);
    let map = map.try_into()?;
    Ok(map)
}

pub(crate) fn load_nodeport_rev_nat_map()
-> Result<HashMap<MapData, NodePortRevNatV4Key, NodePortRevNatV4Value>> {
    let map = MapData::from_pin(BPF_MAP_NODEPORT_REV_NAT_V4.path())?;
    let map = Map::LruHashMap(map);
    let map = map.try_into()?;
    Ok(map)
}

fn cleanup_map(map: &mut HashMap<MapData, ConntrackKeyV4, ConntrackValue>) -> Result<()> {
    let now = monotonic_ns()?;
    let mut expired = Vec::new();

    for entry in map.iter() {
        let (key, value) = entry?;
        let timeout = timeout_for_proto(key.proto, value.tcp_state());
        if now.saturating_sub(value.last_seen_ns) > timeout {
            expired.push(key);
        }
    }

    for key in expired {
        map.remove(&key)?;
    }

    Ok(())
}

fn cleanup_nodeport_map(
    map: &mut HashMap<MapData, NodePortConntrackV4Key, NodePortConntrackV4Value>,
    rev_nat_map: &mut HashMap<MapData, NodePortRevNatV4Key, NodePortRevNatV4Value>,
) -> Result<()> {
    let now = monotonic_ns()?;
    let mut expired = Vec::new();

    for entry in map.iter() {
        let (key, value) = entry?;
        let timeout = nodeport_timeout_for_proto(value.protocol, value.tcp_state());
        if now.saturating_sub(value.last_seen_ns) > timeout {
            expired.push((key, value));
        }
    }

    for (key, value) in expired {
        let rev_nat_key = NodePortRevNatV4Key::new_egress(
            u32::from_be(value.dst_ip),
            key.src_ip(),
            u16::from_be(value.dst_port),
            key.src_port(),
            value.protocol,
        );
        let _ = rev_nat_map.remove(&rev_nat_key);
        map.remove(&key)?;
    }

    Ok(())
}

fn timeout_for_proto(proto: u8, tcp_state: TcpState) -> u64 {
    // TODO: re-examine these for more appropriate values
    match proto {
        1 => CT_TIMEOUT_UDP_NS,
        6 => match tcp_state {
            TcpState::Syn => CT_TIMEOUT_TCP_SYN_NS,
            TcpState::Established => CT_TIMEOUT_TCP_ESTABLISHED_NS,
            TcpState::FinInitiator | TcpState::FinResponder => CT_TIMEOUT_TCP_ESTABLISHED_NS,
            TcpState::Closed => CT_TIMEOUT_TCP_FIN_NS,
            TcpState::Rst => CT_TIMEOUT_TCP_RST_NS,
            TcpState::None => CT_TIMEOUT_TCP_SYN_NS,
        },
        17 => CT_TIMEOUT_UDP_NS,
        58 => CT_TIMEOUT_UDP_NS,
        132 => CT_TIMEOUT_UDP_NS,
        _ => CT_TIMEOUT_UDP_NS,
    }
}

fn nodeport_timeout_for_proto(proto: u8, tcp_state: TcpState) -> u64 {
    timeout_for_proto(proto, tcp_state)
}

fn monotonic_ns() -> Result<u64> {
    let ts = clock_gettime(ClockId::CLOCK_MONOTONIC)?;
    Ok((ts.tv_sec() as u64).saturating_mul(1_000_000_000) + ts.tv_nsec() as u64)
}
