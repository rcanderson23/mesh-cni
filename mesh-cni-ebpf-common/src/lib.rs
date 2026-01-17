#![no_std]

pub mod service;

use core::{
    fmt::Display,
    hash::Hash,
    net::{IpAddr, Ipv6Addr},
};

pub type IdentityId = u32;
pub type Id = u16;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Ip {
    pub octets: [u8; 16],
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Ip {}

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

impl From<Ip> for IpAddr {
    fn from(value: Ip) -> Self {
        let octets = u128::from_ne_bytes(value.octets);
        let ipv6 = Ipv6Addr::from_bits(octets);
        if let Some(ipv4) = ipv6.to_ipv4() {
            IpAddr::V4(ipv4)
        } else {
            IpAddr::V6(ipv6)
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub enum KubeProtocol {
    #[default]
    Tcp = 6,
    Udp = 17,
    Sctp = 132,
}

impl TryFrom<&str> for KubeProtocol {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "TCP" | "tcp" | "Tcp" => Ok(KubeProtocol::Tcp),
            "UDP" | "udp" | "Udp" => Ok(KubeProtocol::Udp),
            "SCTP" | "sctp" | "Sctp" => Ok(KubeProtocol::Sctp),
            _ => Err(
                "Protocol provided is not a valid kube protocol. Only TCP, UDP, or SCTP allowed",
            ),
        }
    }
}

impl Display for KubeProtocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KubeProtocol::Tcp => write!(f, "TCP"),
            KubeProtocol::Udp => write!(f, "UDP"),
            KubeProtocol::Sctp => write!(f, "SCTP"),
        }
    }
}

impl TryFrom<u32> for KubeProtocol {
    type Error = &'static str;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let proto = match value {
            6 => KubeProtocol::Tcp,
            17 => KubeProtocol::Udp,
            132 => KubeProtocol::Sctp,
            _ => {
                return Err(
                    "Protocol provided is not a valid kube protocol. Only TCP, UDP, or SCTP allowed",
                );
            }
        };
        Ok(proto)
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for KubeProtocol {}
