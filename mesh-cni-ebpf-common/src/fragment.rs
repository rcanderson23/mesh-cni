#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FragmentKeyV4 {
    /// Stored in host order
    pub src_ip: u32,
    /// Stored in host order
    pub dst_ip: u32,
    /// Stored in host order
    pub id: u16,
    /// Stored in host order
    pub protocol: u8,
    pub _pad: [u8; 3],
}

impl FragmentKeyV4 {
    pub fn new(src_ip: u32, dst_ip: u32, id: u16, protocol: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            id,
            protocol,
            _pad: [0; 3],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FragmentValue {
    /// Time of creation
    pub created_ns: u64,
    /// Stored in host order
    pub src_port: u16,
    /// Stored in host order
    pub dst_port: u16,
    pub _pad: [u8; 4],
}

impl FragmentValue {
    pub fn new(src_port: u16, dst_port: u16, created_ns: u64) -> Self {
        Self {
            src_port,
            dst_port,
            created_ns,
            _pad: [0; 4],
        }
    }
}
