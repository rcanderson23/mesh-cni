#![no_std]

pub mod egress;
pub mod ingress;
pub mod service;

use aya_ebpf::macros::map;
use aya_ebpf::maps::lpm_trie::Key as LpmKey;
use aya_ebpf::maps::{HashMap, LpmTrie};
use mesh_cni_ebpf_common::Id;
use mesh_cni_ebpf_common::service::{
    EndpointKey, EndpointValueV4, EndpointValueV6, ServiceKeyV4, ServiceKeyV6, ServiceValue,
};

#[map]
static IPV4_IDENTITY: LpmTrie<u32, Id> = LpmTrie::with_max_entries(65535, 0);

#[map]
static IPV6_IDENTITY: LpmTrie<u128, Id> = LpmTrie::with_max_entries(65535, 0);

#[map]
static SERVICES_V4: HashMap<ServiceKeyV4, ServiceValue> = HashMap::with_max_entries(65535, 0);

#[map]
static SERVICES_V6: HashMap<ServiceKeyV6, ServiceValue> = HashMap::with_max_entries(65535, 0);

#[map]
static ENDPOINTS_V4: HashMap<EndpointKey, EndpointValueV4> = HashMap::with_max_entries(65535, 0);

#[map]
static ENDPOINTS_V6: HashMap<EndpointKey, EndpointValueV6> = HashMap::with_max_entries(65535, 0);

#[inline]
fn ipv4_id(ip: LpmKey<u32>) -> Option<Id> {
    IPV4_IDENTITY.get(&ip).copied()
}

#[inline]
fn _ipv6_id(ip: LpmKey<u128>) -> Option<Id> {
    IPV6_IDENTITY.get(&ip).copied()
}
