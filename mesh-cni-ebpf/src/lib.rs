#![no_std]

pub mod egress;
pub mod ingress;
pub mod service;

use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use mesh_cni_common::{EndpointKey, EndpointValue, Id, Ip, ServiceKey, ServiceValue};

#[map]
static IP_IDENTITY: HashMap<Ip, Id> = HashMap::with_max_entries(65535, 0);

#[map]
static SERVICES: HashMap<ServiceKey, ServiceValue> = HashMap::with_max_entries(65535, 0);

#[map]
static ENDPOINTS: HashMap<EndpointKey, EndpointValue> = HashMap::with_max_entries(65535, 0);

#[inline]
fn ip_id(ip: Ip) -> Option<Id> {
    unsafe { IP_IDENTITY.get(&ip).copied() }
}
