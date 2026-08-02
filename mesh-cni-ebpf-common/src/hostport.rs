#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HostPortKey {
    V4(HostPortKeyV4),
    V6(HostPortKeyV6),
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct HostPortKeyV4 {
    pub ip: u32,
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for HostPortKeyV4 {}

impl HostPortKeyV4 {
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
pub struct HostPortKeyV6 {
    pub ip: u128,
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for HostPortKeyV6 {}

impl HostPortKeyV6 {
    pub const fn new(ip: u128, port: u16, protocol: u8) -> Self {
        Self {
            ip,
            port,
            protocol,
            _pad: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HostPortValue {
    V4(HostPortValueV4),
    V6(HostPortValueV6),
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct HostPortValueV4 {
    pub ip: u32,
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for HostPortValueV4 {}

impl HostPortValueV4 {
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
pub struct HostPortValueV6 {
    pub ip: u128,
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for HostPortValueV6 {}

impl HostPortValueV6 {
    pub const fn new(ip: u128, port: u16, protocol: u8) -> Self {
        Self {
            ip,
            port,
            protocol,
            _pad: 0,
        }
    }
}
