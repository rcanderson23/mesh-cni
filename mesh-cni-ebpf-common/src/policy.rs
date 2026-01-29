use core::fmt::Display;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PolicyKey {
    pub src_id: u32,
    pub dst_id: u32,
    /// Value of 0 is used for wildcard
    pub dst_port: u16,
    /// Value of 0 is used for wildcard
    pub proto: u8,
    pub _pad: [u8; 3],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyKey {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyValue {
    /// Value of 0 indicates allow, 1 indicates deny
    pub action: u8,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub enum Action {
    #[default]
    Allow = 0,
    Deny = 1,
}

impl Display for Action {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Action::Allow => write!(f, "ALLOW"),
            Action::Deny => write!(f, "DENY"),
        }
    }
}

impl From<u8> for Action {
    fn from(value: u8) -> Self {
        match value {
            0 => Action::Allow,
            _ => Action::Deny,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyValue {}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub enum PolicyProtocol {
    #[default]
    Any = 0,
    Tcp = 6,
    Udp = 17,
    Sctp = 132,
    Unknown = 255,
}

impl Display for PolicyProtocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PolicyProtocol::Any => write!(f, "ANY"),
            PolicyProtocol::Tcp => write!(f, "TCP"),
            PolicyProtocol::Udp => write!(f, "UDP"),
            PolicyProtocol::Sctp => write!(f, "SCTP"),
            PolicyProtocol::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl From<u8> for PolicyProtocol {
    fn from(value: u8) -> Self {
        match value {
            0 => PolicyProtocol::Any,
            6 => PolicyProtocol::Tcp,
            17 => PolicyProtocol::Udp,
            132 => PolicyProtocol::Sctp,
            _ => PolicyProtocol::Unknown,
        }
    }
}
