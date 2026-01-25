#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ConntrackKeyV4 {
    /// Stored in host order
    pub src_ip: u32,
    /// Stored in host order
    pub dst_ip: u32,
    /// Stored in host order
    pub src_port: u16,
    /// Stored in host order
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConntrackKeyV4 {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConntrackValue {
    pub last_seen_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConntrackValue {}
