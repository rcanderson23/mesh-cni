#![no_std]

use core::fmt::{Display, write};
use core::hash::Hash;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ServiceKey {
    pub ip: Ip,
    pub port: u16,
    pub protocol: KubeProtocol,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ServiceKey {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ServiceValue {
    pub id: Id,
    pub count: u16,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ServiceValue {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EndpointKey {
    pub id: u16,
    pub position: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EndpointKey {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EndpointValue {
    pub ip: Ip,
    pub port: u16,
    pub _protocol: KubeProtocol,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EndpointValue {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub enum KubeProtocol {
    #[default]
    Tcp,
    Udp,
    Sctp,
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

#[cfg(feature = "user")]
unsafe impl aya::Pod for KubeProtocol {}
