use crate::Id;

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
    pub protocol: u8,
    pub _pad: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ServiceKeyV4 {}

impl ServiceKeyV4 {
    pub const fn new(ip: u32, port: u16, protocol: u8) -> Self {
        Self {
            ip,
            port,
            protocol,
            _pad: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ServiceKeyV6 {
    pub ip: u128,
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ServiceKeyV6 {}

impl ServiceKeyV6 {
    pub const fn new(ip: u128, port: u16, protocol: u8) -> Self {
        Self {
            ip,
            port,
            protocol,
            _pad: 0,
        }
    }
}

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
    pub _pad: u32,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EndpointKey {}

impl EndpointKey {
    pub const fn new(id: u16, position: u16) -> Self {
        Self {
            id,
            position,
            _pad: 0,
        }
    }
}

impl ServiceKey {
    pub const fn v4(ip: u32, port: u16, protocol: u8) -> Self {
        ServiceKey::V4(ServiceKeyV4::new(ip, port, protocol))
    }

    pub const fn v6(ip: u128, port: u16, protocol: u8) -> Self {
        ServiceKey::V6(ServiceKeyV6::new(ip, port, protocol))
    }
}

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
    pub _protocol: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EndpointValueV4 {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EndpointValueV6 {
    pub ip: u128,
    pub port: u16,
    pub _protocol: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EndpointValueV6 {}
