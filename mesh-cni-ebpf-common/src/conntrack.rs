use crate::{IdentityId, KubeProtocol};

/// TCP Syn timeout for 120 seconds
pub const CT_TIMEOUT_TCP_SYN_NS: u64 = 120 * 1_000_000_000;
/// TCP Established timeout for 12 hours
pub const CT_TIMEOUT_TCP_ESTABLISHED_NS: u64 = 60 * 60 * 12 * 1_000_000_000;
/// TCP Fin timeout for 30 seconds
pub const CT_TIMEOUT_TCP_FIN_NS: u64 = 30 * 1_000_000_000;
/// TCP Rst timeout for 5 seconds
pub const CT_TIMEOUT_TCP_RST_NS: u64 = 5 * 1_000_000_000;
/// TCP UDP timeout for 60 seconds
pub const CT_TIMEOUT_UDP_NS: u64 = 60 * 1_000_000_000;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpState {
    None = 0,
    Syn = 1,
    Established = 2,
    FinInitiator = 3,
    FinResponder = 4,
    Closed = 5,
    Rst = 6,
}

impl TryFrom<u8> for TcpState {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let state = match value {
            0 => Self::None,
            1 => Self::Syn,
            2 => Self::Established,
            3 => Self::FinInitiator,
            4 => Self::FinResponder,
            5 => Self::Closed,
            6 => Self::Rst,
            _ => return Err(()),
        };
        Ok(state)
    }
}

impl TcpState {
    pub fn from_packet(
        proto: KubeProtocol,
        tcp_flags: Option<TcpFlags>,
        is_reply: bool,
    ) -> Option<Self> {
        if proto != KubeProtocol::Tcp {
            return None;
        }
        let Some(flags) = tcp_flags else {
            return Some(Self::None);
        };
        if flags.rst {
            return Some(Self::Rst);
        }
        if flags.fin {
            return Some(if is_reply {
                Self::FinResponder
            } else {
                Self::FinInitiator
            });
        }
        if flags.syn && flags.ack {
            return Some(Self::Syn);
        }
        if flags.syn && !flags.ack {
            return Some(Self::Syn);
        }
        if flags.ack && !flags.syn {
            return Some(Self::Established);
        }
        Some(Self::None)
    }

    pub fn advance(self, candidate: Option<Self>) -> Self {
        let Some(candidate) = candidate else {
            return self;
        };

        if matches!(candidate, Self::Rst) {
            return Self::Rst;
        }
        if matches!(self, Self::Rst | Self::Closed) {
            return if candidate == Self::Syn {
                Self::Syn
            } else {
                self
            };
        }
        if self.is_half_closed() {
            if self == Self::FinInitiator && candidate == Self::FinResponder {
                return Self::Closed;
            }
            if self == Self::FinResponder && candidate == Self::FinInitiator {
                return Self::Closed;
            }
            return self;
        }
        if self == Self::Established && candidate == Self::Syn {
            return Self::Established;
        }

        candidate
    }

    pub const fn is_half_closed(self) -> bool {
        matches!(self, Self::FinInitiator | Self::FinResponder)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

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
    pub initiator_id: IdentityId,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConntrackKeyV4 {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConntrackValue {
    pub last_seen_ns: u64,
    pub tcp_state: u8,
    pub _pad: [u8; 7],
}

impl ConntrackValue {
    pub const fn new(last_seen_ns: u64, tcp_state: TcpState) -> Self {
        Self {
            last_seen_ns,
            tcp_state: tcp_state as u8,
            _pad: [0; 7],
        }
    }

    pub fn from_packet(proto: KubeProtocol, now: u64, tcp_flags: Option<TcpFlags>) -> Self {
        let tcp_state = match TcpState::from_packet(proto, tcp_flags, false) {
            Some(state) => state,
            None => TcpState::None,
        };
        Self::new(now, tcp_state)
    }

    pub fn tcp_state(&self) -> TcpState {
        TcpState::try_from(self.tcp_state).unwrap_or(TcpState::None)
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConntrackValue {}

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

#[cfg(feature = "user")]
unsafe impl aya::Pod for NodePortConntrackV4Key {}

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

    pub const fn src_ip(&self) -> u32 {
        self.src_ip
    }

    pub const fn src_port(&self) -> u16 {
        self.src_port
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct NodePortConntrackV4Value {
    pub dst_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub tcp_state: u8,
    pub last_seen_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NodePortConntrackV4Value {}

impl NodePortConntrackV4Value {
    pub const fn new(
        dst_ip: u32,
        dst_port: u16,
        protocol: u8,
        tcp_state: TcpState,
        last_seen_ns: u64,
    ) -> Self {
        Self {
            dst_ip,
            dst_port,
            protocol,
            tcp_state: tcp_state as u8,
            last_seen_ns,
        }
    }

    pub fn tcp_state(&self) -> TcpState {
        TcpState::try_from(self.tcp_state).unwrap_or(TcpState::None)
    }
}

#[cfg(test)]
mod tests {
    use super::{TcpFlags, TcpState};
    use crate::KubeProtocol;

    #[test]
    fn classifies_fin_by_direction() {
        let flags = Some(TcpFlags {
            syn: false,
            ack: true,
            fin: true,
            rst: false,
        });

        assert_eq!(
            TcpState::from_packet(KubeProtocol::Tcp, flags, false),
            Some(TcpState::FinInitiator)
        );
        assert_eq!(
            TcpState::from_packet(KubeProtocol::Tcp, flags, true),
            Some(TcpState::FinResponder)
        );
    }

    #[test]
    fn closes_after_both_fins() {
        assert_eq!(
            TcpState::FinInitiator.advance(Some(TcpState::FinResponder)),
            TcpState::Closed
        );
        assert_eq!(
            TcpState::FinResponder.advance(Some(TcpState::FinInitiator)),
            TcpState::Closed
        );
    }

    #[test]
    fn keeps_half_closed_state_on_tail_ack() {
        assert_eq!(
            TcpState::FinInitiator.advance(Some(TcpState::Established)),
            TcpState::FinInitiator
        );
    }

    #[test]
    fn classifies_syn_ack_as_syn() {
        let flags = Some(TcpFlags {
            syn: true,
            ack: true,
            fin: false,
            rst: false,
        });

        assert_eq!(
            TcpState::from_packet(KubeProtocol::Tcp, flags, true),
            Some(TcpState::Syn)
        );
        assert_eq!(TcpState::Syn.advance(Some(TcpState::Syn)), TcpState::Syn);
    }

    #[test]
    fn reopens_closed_or_reset_state_on_fresh_syn() {
        assert_eq!(TcpState::Closed.advance(Some(TcpState::Syn)), TcpState::Syn);
        assert_eq!(TcpState::Rst.advance(Some(TcpState::Syn)), TcpState::Syn);
    }

    #[test]
    fn does_not_reopen_closed_or_reset_state_on_non_syn() {
        assert_eq!(
            TcpState::Closed.advance(Some(TcpState::Established)),
            TcpState::Closed
        );
        assert_eq!(
            TcpState::Rst.advance(Some(TcpState::Established)),
            TcpState::Rst
        );
    }
}
