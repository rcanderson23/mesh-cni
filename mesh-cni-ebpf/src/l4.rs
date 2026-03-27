use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::generated::bpf_ktime_get_ns,
    programs::TcContext,
};
use mesh_cni_ebpf_common::{conntrack::TcpFlags, fragment::FragmentKeyV4};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, sctp::SctpHdr, tcp::TcpHdr, udp::UdpHdr};

use crate::{
    FRAGMENT_V4,
    fragment::{FRAG_TIMEOUT, is_last_frag_v4, is_middle_frag_v4},
};

#[repr(C)]
pub(crate) struct L4Check {
    pub src_port: u16,
    pub dst_port: u16,
    pub should_insert: u8,
    pub has_tcp_flags: u8,
    pub tcp_flags: u8,
    pub _pad: [u8; 1],
}

impl L4Check {
    #[inline]
    fn new(src_port: u16, dst_port: u16, should_insert: bool) -> Self {
        Self {
            src_port,
            dst_port,
            should_insert: should_insert as u8,
            has_tcp_flags: 0,
            tcp_flags: 0,
            _pad: [0; 1],
        }
    }

    #[inline]
    fn with_tcp_flags(mut self, flags: TcpFlags) -> Self {
        self.has_tcp_flags = 1;
        self.tcp_flags = flags.0;
        self
    }

    #[inline]
    pub(crate) fn should_insert(&self) -> bool {
        self.should_insert != 0
    }

    #[inline]
    pub(crate) fn tcp_flags(&self) -> Option<TcpFlags> {
        if self.has_tcp_flags == 0 {
            return None;
        }

        Some(TcpFlags(self.tcp_flags))
    }
}

#[inline]
pub(crate) fn l4_header_check(ctx: &TcContext, ipv4hdr: &Ipv4Hdr) -> Result<L4Check, i32> {
    let src_ip = u32::from_be_bytes(ipv4hdr.src_addr);
    let dst_ip = u32::from_be_bytes(ipv4hdr.dst_addr);
    let ihl = ipv4hdr.ihl() as usize;
    let (src_port, dst_port, should_insert, tcp_flags) =
        if is_middle_frag_v4(ipv4hdr) || is_last_frag_v4(ipv4hdr) {
            let key = FragmentKeyV4::new(src_ip, dst_ip, ipv4hdr.id(), ipv4hdr.proto as u8);

            // Fail close on missing fragments to properly enforce network policy
            let Some(value) = (unsafe { FRAGMENT_V4.get(key).copied() }) else {
                return Err(TC_ACT_SHOT);
            };
            let now = unsafe { bpf_ktime_get_ns() };
            let age = now.saturating_sub(value.created_ns);
            if age > FRAG_TIMEOUT {
                let _ = FRAGMENT_V4.remove(key);
                return Err(TC_ACT_SHOT);
            }

            (value.src_port, value.dst_port, false, None)
        } else {
            match ipv4hdr.proto {
                network_types::ip::IpProto::Tcp => {
                    let tcphdr: TcpHdr = ctx.load(EthHdr::LEN + ihl).map_err(|_| TC_ACT_PIPE)?;
                    let syn = tcphdr.syn() == 1;
                    let ack = tcphdr.ack() == 1;
                    let fin = tcphdr.fin() == 1;
                    let rst = tcphdr.rst() == 1;
                    (
                        u16::from_be_bytes(tcphdr.source),
                        u16::from_be_bytes(tcphdr.dest),
                        syn && !ack,
                        Some(TcpFlags::new(syn, ack, fin, rst)),
                    )
                }
                network_types::ip::IpProto::Udp => {
                    let udphdr: UdpHdr = ctx.load(EthHdr::LEN + ihl).map_err(|_| TC_ACT_PIPE)?;
                    (
                        u16::from_be_bytes(udphdr.src),
                        u16::from_be_bytes(udphdr.dst),
                        true,
                        None,
                    )
                }
                network_types::ip::IpProto::Sctp => {
                    let sctphdr: SctpHdr = ctx.load(EthHdr::LEN + ihl).map_err(|_| TC_ACT_PIPE)?;
                    (
                        u16::from_be_bytes(sctphdr.src),
                        u16::from_be_bytes(sctphdr.dst),
                        true,
                        None,
                    )
                }
                _ => return Err(TC_ACT_PIPE),
            }
        };

    let check = L4Check::new(src_port, dst_port, should_insert);
    Ok(match tcp_flags {
        Some(flags) => check.with_tcp_flags(flags),
        None => check,
    })
}
