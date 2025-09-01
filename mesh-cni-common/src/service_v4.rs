use crate::{Id, KubeProtocol};

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
pub struct ServiceValueV4 {
    pub id: Id,
    pub count: u16,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ServiceValueV4 {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EndpointKeyV4 {
    pub id: u16,
    pub position: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EndpointKeyV4 {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EndpointValueV4 {
    pub ip: u32,
    pub port: u16,
    pub _protocol: KubeProtocol,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EndpointValueV4 {}
