#![no_std]

pub mod egress;
pub mod ingress;
pub mod service;

use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use mesh_cni_common::{Destination, Ip, IpStateId};

#[map]
static IP_IDENTITY: HashMap<Ip, IpStateId> = HashMap::<Ip, IpStateId>::with_max_entries(65535, 0);

#[map]
static SERVICES: HashMap<Destination, [Destination; 4]> =
    HashMap::<Destination, [Destination; 4]>::with_max_entries(65535, 0);

#[inline]
fn ip_id(ip: Ip) -> Option<IpStateId> {
    unsafe { IP_IDENTITY.get(&ip).copied() }
}
