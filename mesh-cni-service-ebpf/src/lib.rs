#![no_std]

pub mod service;

use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, LpmTrie};
use mesh_cni_ebpf_common::Id;
use mesh_cni_ebpf_common::service::{
    EndpointKey, EndpointValueV4, EndpointValueV6, ServiceKeyV4, ServiceKeyV6, ServiceValue,
};

#[map(name = "identity_v4")]
static IDENTITY_V4: LpmTrie<u32, Id> = LpmTrie::with_max_entries(65535, 0);

#[map(name = "identity_v6")]
static IDENTITY_V6: LpmTrie<u128, Id> = LpmTrie::with_max_entries(65535, 0);

#[map(name = "services_v4")]
static SERVICES_V4: HashMap<ServiceKeyV4, ServiceValue> = HashMap::with_max_entries(65535, 0);

#[map(name = "services_v6")]
static SERVICES_V6: HashMap<ServiceKeyV6, ServiceValue> = HashMap::with_max_entries(65535, 0);

#[map(name = "endpoints_v4")]
static ENDPOINTS_V4: HashMap<EndpointKey, EndpointValueV4> = HashMap::with_max_entries(65535, 0);

#[map(name = "endpoints_v6")]
static ENDPOINTS_V6: HashMap<EndpointKey, EndpointValueV6> = HashMap::with_max_entries(65535, 0);
