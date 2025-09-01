#![no_std]

pub mod egress;
pub mod ingress;
pub mod service;

use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use mesh_cni_common::service_v4::{EndpointKeyV4, EndpointValueV4, ServiceKeyV4, ServiceValueV4};
use mesh_cni_common::{Id, Ip};

#[map]
static IP_IDENTITY: HashMap<Ip, Id> = HashMap::with_max_entries(65535, 0);

#[map]
static SERVICES: HashMap<ServiceKeyV4, ServiceValueV4> = HashMap::with_max_entries(65535, 0);

#[map]
static ENDPOINTS: HashMap<EndpointKeyV4, EndpointValueV4> = HashMap::with_max_entries(65535, 0);

#[inline]
fn ip_id(ip: Ip) -> Option<Id> {
    unsafe { IP_IDENTITY.get(&ip).copied() }
}
