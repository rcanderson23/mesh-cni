mod convert;
mod state;

use std::net::{Ipv4Addr, Ipv6Addr};

use aya::maps::{LpmTrie, Map, MapData, lpm_trie::Key as LpmKey};
pub(crate) use convert::LpmKeyNetwork;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use kube::Client;
use mesh_cni_ebpf_common::{IdentityId, policy::LOCAL_ID};
use mesh_cni_identity_controller::start_identity_controllers;
pub use state::IpNetworkState;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Result,
    bpf::{BPF_MAP_IDENTITY_V4, BPF_MAP_IDENTITY_V6, BpfMap, IdentityMapV4, IdentityMapV6},
};

pub async fn run<IP4, IP6>(
    kube_client: Client,
    node_name: String,
    ipstate: IpNetworkState<IP4, IP6>,
    cancel: CancellationToken,
) -> Result<()>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = IdentityId> + Send + Sync + 'static,
    IP6: BpfMap<Key = LpmKey<u128>, Value = IdentityId> + Send + Sync + 'static,
{
    bootstrap_default_identities(&ipstate)?;

    let controllers = start_identity_controllers(kube_client, node_name, cancel, ipstate);

    tokio::spawn(controllers);
    Ok(())
}

fn bootstrap_default_identities<IP4, IP6>(ipstate: &IpNetworkState<IP4, IP6>) -> Result<()>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = IdentityId> + Send + Sync + 'static,
    IP6: BpfMap<Key = LpmKey<u128>, Value = IdentityId> + Send + Sync + 'static,
{
    let defaults = [
        IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(127, 0, 0, 0), 8)?),
        // Keep both loopback and unspecified v6 as reserved to avoid dropping local-stack flows.
        IpNetwork::V6(Ipv6Network::new(Ipv6Addr::LOCALHOST, 128)?),
        IpNetwork::V6(Ipv6Network::new(Ipv6Addr::UNSPECIFIED, 128)?),
    ];

    for network in defaults {
        ipstate.update(network, LOCAL_ID)?;
    }
    Ok(())
}

pub fn load_maps() -> Result<(IdentityMapV4, IdentityMapV6)> {
    info!("loading v4 identity map");
    let ipv4_map = MapData::from_pin(BPF_MAP_IDENTITY_V4.path())?;
    let ipv4_map = Map::LpmTrie(ipv4_map);
    info!("converting v4 identity map");
    let ipv4_map: LpmTrie<MapData, u32, IdentityId> = ipv4_map.try_into()?;

    info!("loading v6 identity map");
    let ipv6_map = MapData::from_pin(BPF_MAP_IDENTITY_V6.path())?;
    let ipv6_map = Map::LpmTrie(ipv6_map);
    let ipv6_map: LpmTrie<MapData, u128, IdentityId> = ipv6_map.try_into()?;

    Ok((ipv4_map, ipv6_map))
}
