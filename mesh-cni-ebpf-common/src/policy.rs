use core::fmt::Display;

pub const ANY_ID: u32 = 1;

pub const ANY_PORT: u16 = 0;

pub const ANY_DIR: u8 = 0;

pub const RULESET_NONE: u32 = 0;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub enum PolicyDirection {
    #[default]
    Any = 0,
    Ingress = 1,
    Egress = 2,
}

impl PolicyDirection {
    pub const fn any_u8() -> u8 {
        PolicyDirection::Any as u8
    }

    pub const fn ingress_u8() -> u8 {
        PolicyDirection::Ingress as u8
    }

    pub const fn egress_u8() -> u8 {
        PolicyDirection::Egress as u8
    }
}

impl Display for PolicyDirection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PolicyDirection::Any => write!(f, "ANY"),
            PolicyDirection::Ingress => write!(f, "INGRESS"),
            PolicyDirection::Egress => write!(f, "EGRESS"),
        }
    }
}

impl From<u8> for PolicyDirection {
    fn from(value: u8) -> Self {
        match value {
            1 => PolicyDirection::Ingress,
            2 => PolicyDirection::Egress,
            _ => PolicyDirection::Any,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PolicyIndexKey {
    pub src_id: u32,
    pub dst_id: u32,
    pub direction: u8,
    pub _pad: [u8; 3],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyIndexKey {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PolicyRuleKey {
    pub ruleset_id: u32,
    pub proto: u8,
    pub _pad0: [u8; 3],
    pub port: u16,
    pub _pad1: [u8; 2],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyRuleKey {}

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

impl Action {
    pub const fn allow_u8() -> u8 {
        Action::Allow as u8
    }

    pub const fn deny_u8() -> u8 {
        Action::Deny as u8
    }
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

impl PolicyProtocol {
    pub const fn any_u8() -> u8 {
        PolicyProtocol::Any as u8
    }

    pub const fn tcp_u8() -> u8 {
        PolicyProtocol::Tcp as u8
    }

    pub const fn udp_u8() -> u8 {
        PolicyProtocol::Udp as u8
    }

    pub const fn sctp_u8() -> u8 {
        PolicyProtocol::Sctp as u8
    }
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
