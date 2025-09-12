#![no_std]

pub mod egress;
pub mod ingress;
pub mod service;

use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use mesh_cni_common::Id;
use mesh_cni_common::service::{
    EndpointKey, EndpointValueV4, EndpointValueV6, ServiceKeyV4, ServiceKeyV6, ServiceValue,
};

#[map]
static IPV4_IDENTITY: HashMap<u32, Id> = HashMap::with_max_entries(65535, 0);

#[map]
static IPV6_IDENTITY: HashMap<u128, Id> = HashMap::with_max_entries(65535, 0);

#[map]
static SERVICES_V4: HashMap<ServiceKeyV4, ServiceValue> = HashMap::with_max_entries(65535, 0);

#[map]
static SERVICES_V6: HashMap<ServiceKeyV6, ServiceValue> = HashMap::with_max_entries(65535, 0);

#[map]
static ENDPOINTS_V4: HashMap<EndpointKey, EndpointValueV4> = HashMap::with_max_entries(65535, 0);

#[map]
static ENDPOINTS_V6: HashMap<EndpointKey, EndpointValueV6> = HashMap::with_max_entries(65535, 0);

#[inline]
fn ipv4_id(ip: u32) -> Option<Id> {
    unsafe { IPV4_IDENTITY.get(&ip).copied() }
}
