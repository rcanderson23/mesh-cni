#![no_std]

pub mod egress;
pub mod ingress;
pub mod service;

use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use homelab_cni_common::{Ip, IpStateId};

#[map]
static IP_IDENTITY: HashMap<Ip, IpStateId> = HashMap::<Ip, IpStateId>::with_max_entries(65535, 0);

#[inline]
fn ip_id(ip: Ip) -> Option<IpStateId> {
    unsafe { IP_IDENTITY.get(&ip).copied() }
}
