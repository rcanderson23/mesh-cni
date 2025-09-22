use crate::{Id, KubeProtocol};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ServiceKey {
    V4(ServiceKeyV4),
    V6(ServiceKeyV6),
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ServiceKeyV4 {
    pub ip: u32,
    pub port: u16,
    pub protocol: KubeProtocol,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ServiceKeyV4 {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ServiceKeyV6 {
    pub ip: u128,
    pub port: u16,
    pub protocol: KubeProtocol,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ServiceKeyV6 {}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EndpointValue {
    V4(EndpointValueV4),
    V6(EndpointValueV6),
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EndpointValueV4 {
    pub ip: u32,
    pub port: u16,
    pub _protocol: KubeProtocol,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EndpointValueV4 {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EndpointValueV6 {
    pub ip: u128,
    pub port: u16,
    pub _protocol: KubeProtocol,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EndpointValueV6 {}
