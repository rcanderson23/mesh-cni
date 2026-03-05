#![no_std]

pub mod egress;
pub mod ingress;
pub(crate) mod policy;
pub mod service;

use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, LpmTrie, LruHashMap, lpm_trie::Key as LpmKey},
};
use mesh_cni_ebpf_common::{
    IdentityId,
    conntrack::{ConntrackKeyV4, ConntrackValue},
    policy::{
        CidrPolicyMapDataV4, CidrPolicyMapDataV6, PolicyIndexKey, PolicyRuleKey, PolicyValue,
        RulesetId,
    },
    service::{
        EndpointKey, EndpointValueV4, EndpointValueV6, NodePortKey, ServiceKeyV4, ServiceKeyV6,
        ServiceValue,
    },
};

#[map(name = "identity_v4")]
static IDENTITY_V4: LpmTrie<u32, IdentityId> = LpmTrie::with_max_entries(65535, 0);

#[map(name = "identity_v6")]
static IDENTITY_V6: LpmTrie<u128, IdentityId> = LpmTrie::with_max_entries(65535, 0);

#[map(name = "conntrack_v4")]
static CONNTRACK_V4: LruHashMap<ConntrackKeyV4, ConntrackValue> =
    LruHashMap::with_max_entries(65535, 0);

#[map(name = "policy_index")]
static POLICY_INDEX: HashMap<PolicyIndexKey, RulesetId> = HashMap::with_max_entries(65535, 0);

#[map(name = "policy_ruleset")]
static POLICY_RULESET: HashMap<PolicyRuleKey, PolicyValue> = HashMap::with_max_entries(65535, 0);

#[map(name = "policy_cidr_v4")]
static POLICY_CIDR_V4: LpmTrie<CidrPolicyMapDataV4, RulesetId> =
    LpmTrie::with_max_entries(65535, 0);

#[map(name = "policy_cidr_v6")]
static POLICY_CIDR_V6: LpmTrie<CidrPolicyMapDataV6, RulesetId> =
    LpmTrie::with_max_entries(65535, 0);

#[map(name = "services_v4")]
static SERVICES_V4: HashMap<ServiceKeyV4, ServiceValue> = HashMap::with_max_entries(65535, 0);

#[map(name = "services_v6")]
static SERVICES_V6: HashMap<ServiceKeyV6, ServiceValue> = HashMap::with_max_entries(65535, 0);

#[map(name = "endpoints_v4")]
static ENDPOINTS_V4: HashMap<EndpointKey, EndpointValueV4> = HashMap::with_max_entries(65535, 0);

#[map(name = "endpoints_v6")]
static ENDPOINTS_V6: HashMap<EndpointKey, EndpointValueV6> = HashMap::with_max_entries(65535, 0);

#[map(name = "nodeport_iface_indexes")]
static NODEPORT_IFACE_INDEXES: Array<u32> = Array::with_max_entries(2, 0);

#[map(name = "nodeport_local_addrs_v4")]
static NODEPORT_LOCAL_ADDRS_V4: HashMap<u32, u8> = HashMap::with_max_entries(65535, 0);

#[map(name = "nodeport_services_v4")]
static NODEPORT_SERVICES_V4: HashMap<NodePortKey, ServiceKeyV4> =
    HashMap::with_max_entries(65535, 0);

#[inline]
fn id_v4(ip: LpmKey<u32>) -> Option<IdentityId> {
    IDENTITY_V4.get(&ip).copied()
}

#[inline]
fn _id_v6(ip: LpmKey<u128>) -> Option<IdentityId> {
    IDENTITY_V6.get(&ip).copied()
}
