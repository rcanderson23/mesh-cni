mod convert;
mod state;

use aya::maps::{LpmTrie, Map, MapData, lpm_trie::Key as LpmKey};
pub(crate) use convert::LpmKeyNetwork;
use kube::Client;
use mesh_cni_ebpf_common::IdentityId;
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
    let controllers = start_identity_controllers(kube_client, node_name, cancel, ipstate);

    tokio::spawn(controllers);
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
