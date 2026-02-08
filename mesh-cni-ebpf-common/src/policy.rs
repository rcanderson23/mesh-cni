use core::fmt::Display;

pub const ANY_ID: u32 = 0;
pub const WORLD_ID: u32 = 1;
pub const RESERVED_IDENTITY_IDS: &[u32] = &[ANY_ID, WORLD_ID];

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
    pub fn opposite(&self) -> PolicyDirection {
        match self {
            PolicyDirection::Any => PolicyDirection::Any,
            PolicyDirection::Ingress => PolicyDirection::Egress,
            PolicyDirection::Egress => PolicyDirection::Ingress,
        }
    }
}

impl From<PolicyDirection> for u8 {
    fn from(value: PolicyDirection) -> Self {
        value as u8
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

impl From<Action> for u8 {
    fn from(value: Action) -> Self {
        value as u8
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

impl From<PolicyProtocol> for u8 {
    fn from(value: PolicyProtocol) -> Self {
        value as u8
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
