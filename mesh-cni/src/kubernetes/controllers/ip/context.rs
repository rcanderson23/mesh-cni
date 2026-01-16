use aya::maps::lpm_trie::Key as LpmKey;
use k8s_openapi::api::core::v1::{Namespace, Pod};
use kube::runtime::reflector::Store;
use mesh_cni_ebpf_common::Id;

use crate::{
    bpf::{BpfMap, ip::IpNetworkState},
    kubernetes::{ClusterId, controllers::metrics::ControllerMetrics},
};

pub(crate) struct Context<IP4, IP6>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = Id>,
    IP6: BpfMap<Key = LpmKey<u128>, Value = Id>,
{
    pub metrics: ControllerMetrics,
    pub ip_state: IpNetworkState<IP4, IP6>,
    pub pod_store: Store<Pod>,
    pub ns_store: Store<Namespace>,
    pub cluster_id: ClusterId,
}
