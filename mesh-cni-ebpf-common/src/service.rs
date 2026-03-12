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

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct NodePortKey {
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NodePortKey {}

impl NodePortKey {
    pub const fn new(port: u16, protocol: u8) -> Self {
        Self {
            port,
            protocol,
            _pad: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct NodePortRevNatV4Key {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NodePortRevNatV4Key {}

impl NodePortRevNatV4Key {
    pub const fn new_ingress(
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            src_ip: dst_ip,
            dst_ip: src_ip,
            src_port: dst_port,
            dst_port: src_port,
            protocol,
            _pad: [0, 0, 0],
        }
    }
    pub const fn new_egress(
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            _pad: [0, 0, 0],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct NodePortRevNatV4Value {
    // src_ip matches to original IP incoming to the host
    pub src_ip: u32,
    // src_port matches to the original port incoming on the the host
    pub src_port: u16,
    pub protocol: u8,
    pub _pad: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NodePortRevNatV4Value {}

impl NodePortRevNatV4Value {
    /// src_ip/scr_port should the original dst_ip/dst_port before DNAT.
    pub const fn new(src_ip: u32, src_port: u16, protocol: u8) -> Self {
        Self {
            src_ip,
            src_port,
            protocol,
            _pad: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct NodePortConntrackV4Key {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    _pad: [u8; 3],
}

impl NodePortConntrackV4Key {
    pub const fn new(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            _pad: [0, 0, 0],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct NodePortConntrackV4Value {
    pub dst_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NodePortConntrackV4Value {}

impl NodePortConntrackV4Value {
    pub const fn new(dst_ip: u32, dst_port: u16, protocol: u8) -> Self {
        Self {
            dst_ip,
            dst_port,
            protocol,
            _pad: 0,
        }
    }
}
