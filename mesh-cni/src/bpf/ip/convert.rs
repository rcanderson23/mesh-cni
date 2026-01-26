use std::net::{Ipv4Addr, Ipv6Addr};

use aya::maps::lpm_trie::Key as LpmKey;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

pub(crate) trait LpmKeyNetwork {
    fn key_to_network(key: LpmKey<Self>) -> IpNetwork
    where
        Self: Sized;
}

impl LpmKeyNetwork for u32 {
    fn key_to_network(key: LpmKey<u32>) -> IpNetwork {
        ip4_key_to_network(key)
    }
}

impl LpmKeyNetwork for u128 {
    fn key_to_network(key: LpmKey<u128>) -> IpNetwork {
        ip6_key_to_network(key)
    }
}

fn ip6_key_to_network(key: LpmKey<u128>) -> IpNetwork {
    let addr = u128::from_be(key.data());
    IpNetwork::V6(Ipv6Network::new(Ipv6Addr::from_bits(addr), key.prefix_len() as u8).unwrap())
}

fn ip4_key_to_network(key: LpmKey<u32>) -> IpNetwork {
    let addr = u32::from_be(key.data());
    IpNetwork::V4(Ipv4Network::new(Ipv4Addr::from_bits(addr), key.prefix_len() as u8).unwrap())
}
