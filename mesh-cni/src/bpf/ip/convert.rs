use std::net::{Ipv4Addr, Ipv6Addr};

use aya::maps::lpm_trie::Key as LpmKey;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

pub(crate) trait LpmKeyNetwork {
    fn key_to_network(key: LpmKey<Self>) -> IpNetwork
    where
        Self: Sized;
    // fn network_to_key(network: IpNetwork) -> Result<LpmKey<Self>>
    // where
    //     Self: Sized;
}

impl LpmKeyNetwork for u32 {
    fn key_to_network(key: LpmKey<u32>) -> IpNetwork {
        ip4_key_to_network(key)
    }

    // fn network_to_key(network: IpNetwork) -> Result<LpmKey<u32>> {
    //     match network {
    //         IpNetwork::V4(network) => Ok(network_to_ip4_key(network)),
    //         IpNetwork::V6(_) => Err(Error::ConversionError(
    //             "expected IPv4 network for LpmKey<u32>".into(),
    //         )),
    //     }
    // }
}

impl LpmKeyNetwork for u128 {
    fn key_to_network(key: LpmKey<u128>) -> IpNetwork {
        ip6_key_to_network(key)
    }

    // fn network_to_key(network: IpNetwork) -> Result<LpmKey<u128>> {
    //     match network {
    //         IpNetwork::V6(network) => Ok(network_to_ip6_key(network)),
    //         IpNetwork::V4(_) => Err(Error::ConversionError(
    //             "expected IPv6 network for LpmKey<u128>".into(),
    //         )),
    //     }
    // }
}

fn ip6_key_to_network(key: LpmKey<u128>) -> IpNetwork {
    let addr = u128::from_be(key.data());
    IpNetwork::V6(
        Ipv6Network::new(Ipv6Addr::from_bits(addr), key.prefix_len() as u8).unwrap(),
    )
}

fn ip4_key_to_network(key: LpmKey<u32>) -> IpNetwork {
    let addr = u32::from_be(key.data());
    IpNetwork::V4(
        Ipv4Network::new(Ipv4Addr::from_bits(addr), key.prefix_len() as u8).unwrap(),
    )
}

// fn network_to_ip6_key(network: Ipv6Network) -> LpmKey<u128> {
//     LpmKey::new(network.prefix() as u32, network.ip().to_bits().to_be())
// }
//
// fn network_to_ip4_key(network: Ipv4Network) -> LpmKey<u32> {
//     LpmKey::new(network.prefix() as u32, network.ip().to_bits().to_be())
// }
