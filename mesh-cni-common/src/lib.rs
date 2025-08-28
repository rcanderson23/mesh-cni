#![no_std]

use core::net::IpAddr;

use network_types::ip::IpProto;

pub type IpStateId = u32;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Ip {
    pub octets: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Destination {
    pub ip: Ip,
    pub port: u16,
}

impl From<IpAddr> for Ip {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ipv4_addr) => {
                let octets = u32::from(ipv4_addr);
                let octets = u128::from(octets).to_ne_bytes();
                Ip { octets }
            }
            IpAddr::V6(ipv6_addr) => {
                let octets = u128::from(ipv6_addr).to_ne_bytes();
                Ip { octets }
            }
        }
    }
}

impl From<u32> for Ip {
    fn from(value: u32) -> Self {
        let octets = u128::from(value).to_ne_bytes();
        Ip { octets }
    }
}

/// Represents a packet destination
/// TODO: consider combining with Target making the proto optional
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DestinationWithProto {
    pub ip: Ip,
    pub port: u16,
    pub protocol: IpProto,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Ip {}
