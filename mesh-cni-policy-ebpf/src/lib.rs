#![no_std]

pub mod ingress;
mod ipv4;

use aya_ebpf::{
    macros::map,
    maps::{HashMap, LpmTrie, LruHashMap, lpm_trie::Key as LpmKey},
};
use mesh_cni_ebpf_common::{
    IdentityId,
    conntrack::{ConntrackKeyV4, ConntrackValue},
    policy::{PolicyKey, PolicyValue},
};

#[map(name = "identity_v4")]
static IDENTITY_V4: LpmTrie<u32, IdentityId> = LpmTrie::with_max_entries(65535, 0);

#[map(name = "identity_v6")]
static IDENTITY_V6: LpmTrie<u128, IdentityId> = LpmTrie::with_max_entries(65535, 0);

#[map(name = "conntrack_v4")]
static CONNTRACK_V4: LruHashMap<ConntrackKeyV4, ConntrackValue> =
    LruHashMap::with_max_entries(65535, 0);

#[map(name = "policy")]
static POLICY: HashMap<PolicyKey, PolicyValue> = HashMap::with_max_entries(65535, 0);

#[inline]
fn id_v4(ip: LpmKey<u32>) -> Option<IdentityId> {
    IDENTITY_V4.get(&ip).copied()
}

#[inline]
fn _id_v6(ip: LpmKey<u128>) -> Option<IdentityId> {
    IDENTITY_V6.get(&ip).copied()
}
