use core::mem::offset_of;

use aya_ebpf::{
    bindings::{BPF_F_MARK_MANGLED_0, BPF_F_PSEUDO_HDR, TC_ACT_PIPE, TC_ACT_SHOT, bpf_sock_addr},
    helpers::generated::bpf_get_prandom_u32,
    programs::{SockAddrContext, TcContext},
};
use aya_log_ebpf::error;
use mesh_cni_ebpf_common::service::{
    EndpointKey, NodePortConntrackV4Key, NodePortConntrackV4Value, NodePortKey,
    NodePortRevNatV4Key, NodePortRevNatV4Value, ServiceKeyV4,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::{
    ENDPOINTS_V4, NODEPORT_CONNTRACK_V4, NODEPORT_LOCAL_ADDRS_V4, NODEPORT_REV_NAT_V4,
    NODEPORT_SERVICES_V4, SERVICES_V4,
};

const AF_INET: u16 = 2;
const _AF_INET6: u16 = 10;

// https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/#context
// Example: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/#example
// struct bpf_sock_addr {
//     __u32 user_family;  /* Allows 4-byte read, but no write. */
//     __u32 user_ip4;     /* Allows 1,2,4-byte read and 4-byte write.
//                 * Stored in network byte order.
//                 */
//     __u32 user_ip6[4];  /* Allows 1,2,4,8-byte read and 4,8-byte write.
//                 * Stored in network byte order.
//                 */
//     __u32 user_port;    /* Allows 1,2,4-byte read and 4-byte write.
//                 * Stored in network byte order
//                 */
//     __u32 family;       /* Allows 4-byte read, but no write */
//     __u32 type;     /* Allows 4-byte read, but no write */
//     __u32 protocol;     /* Allows 4-byte read, but no write */
//     __u32 msg_src_ip4;  /* Allows 1,2,4-byte read and 4-byte write.
//                 * Stored in network byte order.
//                 */
//     __u32 msg_src_ip6[4];   /* Allows 1,2,4,8-byte read and 4,8-byte write.
//                 * Stored in network byte order.
//                 */
//     __bpf_md_ptr(struct bpf_sock *, sk);
// };
//
//

///
/// Return codes [0(deny),1(allow)]
#[inline]
pub fn try_mesh_cni_cgroup_connect4(ctx: SockAddrContext) -> Result<i32, i32> {
    let ptr = ctx.sock_addr;

    if unsafe { *ptr }.user_family != AF_INET as u32 {
        return Ok(1);
    };

    let service_key = build_service_key(&ctx, ptr)?;
    let service_value = unsafe {
        // TODO: investigate this behavior further.
        // Best to copy to avoid aliasing/junk with deletes/updates happening concurrently
        // however there may be better ways to handle this
        match SERVICES_V4.get(service_key).copied() {
            Some(value) => value,
            None => {
                return Ok(1);
            }
        }
    };
    if service_value.count == 0 {
        return Err(0);
    }
    let position = get_position(service_value.count);

    let endpoints_value = unsafe {
        match ENDPOINTS_V4.get(EndpointKey::new(service_value.id, position)) {
            Some(value) => value,
            None => return Ok(1),
        }
    };

    unsafe {
        (*ptr).user_ip4 = endpoints_value.ip.to_be();
        (*ptr).user_port = endpoints_value.port.to_be() as u32;
    }

    Ok(1)
}

#[inline]
fn build_service_key(_ctx: &SockAddrContext, ptr: *mut bpf_sock_addr) -> Result<ServiceKeyV4, i32> {
    let (ip, port, protocol) = unsafe {
        let ip = u32::from_be((*ptr).user_ip4);
        let port = u16::from_be((*ptr).user_port as u16);
        let protocol = (*ptr).protocol.try_into().map_err(|_| 1)?;
        (ip, port, protocol)
    };

    Ok(ServiceKeyV4::new(ip, port, protocol))
}

#[inline]
fn get_position(count: u16) -> u16 {
    let rand = unsafe { bpf_get_prandom_u32() as u16 };
    rand % count
}

// TODO: implement ipv6
// TODO: consider sctp?
#[inline]
pub fn try_mesh_cni_nodeport_ingress(mut ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;
    let Ok(ether_type) = ethhdr.ether_type() else {
        return Ok(TC_ACT_PIPE);
    };
    if !matches!(ether_type, EtherType::Ipv4) {
        return Ok(TC_ACT_PIPE);
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| TC_ACT_PIPE)?;
    let ihl = ipv4hdr.ihl();
    let orig_dst_ip = u32::from_be_bytes(ipv4hdr.dst_addr);

    // pass traffic that isn't pointed at IPs assigned to attached ifaces
    // as this could meant for pods
    if unsafe { NODEPORT_LOCAL_ADDRS_V4.get(orig_dst_ip) }.is_none() {
        return Ok(TC_ACT_PIPE);
    }

    let (orig_dst_port, src_port, proto) = match ipv4hdr.proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = ctx
                .load(EthHdr::LEN + ihl as usize)
                .map_err(|_| TC_ACT_PIPE)?;
            (
                u16::from_be_bytes(tcphdr.dest),
                u16::from_be_bytes(tcphdr.source),
                Protocol::Tcp,
            )
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = ctx
                .load(EthHdr::LEN + ihl as usize)
                .map_err(|_| TC_ACT_PIPE)?;
            (
                u16::from_be_bytes(udphdr.dst),
                u16::from_be_bytes(udphdr.src),
                Protocol::Udp,
            )
        }
        _ => return Ok(TC_ACT_PIPE),
    };

    let nodeport_key = NodePortKey::new(orig_dst_port, proto as u8);
    let Some(service_key) = (unsafe { NODEPORT_SERVICES_V4.get(nodeport_key).copied() }) else {
        return Ok(TC_ACT_PIPE);
    };

    let Some(service_value) = (unsafe { SERVICES_V4.get(service_key).copied() }) else {
        return Ok(TC_ACT_PIPE);
    };
    if service_value.count == 0 {
        return Err(TC_ACT_SHOT);
    }
    let position = get_position(service_value.count);

    let endpoints_value = unsafe {
        match ENDPOINTS_V4.get(EndpointKey::new(service_value.id, position)) {
            Some(value) => value,
            None => return Ok(TC_ACT_PIPE),
        }
    };

    let ipv4_offset = EthHdr::LEN;
    let l4_offset = EthHdr::LEN + ihl as usize;

    let ipv4_check_offset = ipv4_offset + offset_of!(Ipv4Hdr, check);
    let dst_ip_offset = ipv4_offset + offset_of!(Ipv4Hdr, dst_addr);

    let (dst_port_offset, l4_check_offset) = match ipv4hdr.proto {
        IpProto::Tcp => (
            l4_offset + offset_of!(TcpHdr, dest),
            l4_offset + offset_of!(TcpHdr, check),
        ),
        IpProto::Udp => (
            l4_offset + offset_of!(UdpHdr, dst),
            l4_offset + offset_of!(UdpHdr, check),
        ),
        _ => return Ok(TC_ACT_PIPE),
    };

    let src_ip = u32::from_be_bytes(ipv4hdr.src_addr);
    let mut new_dst_ip = endpoints_value.ip.to_be();
    let mut new_dst_port = endpoints_value.port.to_be();
    let l4_ip_flags = proto.l4_ip_flags();
    let l4_port_flags = proto.l4_port_flags();
    let proto = proto as u8;

    let conntrack_key =
        NodePortConntrackV4Key::new(src_ip, orig_dst_ip, src_port, orig_dst_port, proto);
    if let Some(value) = unsafe { NODEPORT_CONNTRACK_V4.get(conntrack_key).copied() } {
        new_dst_ip = value.dst_ip;
        new_dst_port = value.dst_port;
    } else {
        let conntrack_value = NodePortConntrackV4Value::new(new_dst_ip, new_dst_port, proto);
        NODEPORT_CONNTRACK_V4
            .insert(conntrack_key, conntrack_value, 0)
            .map_err(|_| TC_ACT_PIPE)?;
    }

    // Reverse-NAT keys must match reply traffic tuple seen on mesh_pod ingress:
    // backend_ip:backend_port -> client_ip:client_port.
    let rev_nat_key = NodePortRevNatV4Key::new_egress(
        u32::from_be(new_dst_ip),
        src_ip,
        u16::from_be(new_dst_port),
        src_port,
        proto,
    );
    if unsafe { NODEPORT_REV_NAT_V4.get(rev_nat_key) }.is_none() {
        let rev_nat_value =
            NodePortRevNatV4Value::new(orig_dst_ip.to_be(), orig_dst_port.to_be(), proto);
        NODEPORT_REV_NAT_V4
            .insert(rev_nat_key, rev_nat_value, 0)
            .map_err(|_| {
                error!(&ctx, "failed to insert rev nat key");
                TC_ACT_PIPE
            })?;
    }

    ctx.l3_csum_replace(
        ipv4_check_offset,
        orig_dst_ip.to_be() as u64,
        new_dst_ip as u64,
        4,
    )
    .map_err(|_| TC_ACT_PIPE)?;

    ctx.l4_csum_replace(
        l4_check_offset,
        orig_dst_port.to_be() as u64,
        new_dst_port as u64,
        l4_port_flags,
    )
    .map_err(|_| TC_ACT_PIPE)?;

    ctx.l4_csum_replace(
        l4_check_offset,
        orig_dst_ip.to_be() as u64,
        new_dst_ip as u64,
        l4_ip_flags,
    )
    .map_err(|_| TC_ACT_PIPE)?;

    ctx.store(dst_ip_offset, &new_dst_ip, 0)
        .map_err(|_| TC_ACT_PIPE)?;
    ctx.store(dst_port_offset, &new_dst_port, 0)
        .map_err(|_| TC_ACT_PIPE)?;

    Ok(TC_ACT_PIPE)
}

// TODO: implement ipv6
// TODO: consider sctp?
#[inline]
pub fn try_mesh_cni_nodeport_egress(mut ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;
    let Ok(ether_type) = ethhdr.ether_type() else {
        return Ok(TC_ACT_PIPE);
    };
    if !matches!(ether_type, EtherType::Ipv4) {
        return Ok(TC_ACT_PIPE);
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| TC_ACT_PIPE)?;
    let ihl = ipv4hdr.ihl();
    let src_ip = u32::from_be_bytes(ipv4hdr.src_addr);
    let dst_ip = u32::from_be_bytes(ipv4hdr.dst_addr);

    let (src_port, dst_port, proto) = match ipv4hdr.proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = ctx
                .load(EthHdr::LEN + ihl as usize)
                .map_err(|_| TC_ACT_PIPE)?;
            (
                u16::from_be_bytes(tcphdr.source),
                u16::from_be_bytes(tcphdr.dest),
                Protocol::Tcp,
            )
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = ctx
                .load(EthHdr::LEN + ihl as usize)
                .map_err(|_| TC_ACT_PIPE)?;
            (
                u16::from_be_bytes(udphdr.src),
                u16::from_be_bytes(udphdr.dst),
                Protocol::Udp,
            )
        }
        _ => return Ok(TC_ACT_PIPE),
    };

    let ipv4_offset = EthHdr::LEN;
    let l4_offset = EthHdr::LEN + ihl as usize;

    let ipv4_check_offset = ipv4_offset + offset_of!(Ipv4Hdr, check);
    let src_ip_offset = ipv4_offset + offset_of!(Ipv4Hdr, src_addr);

    let (src_port_offset, l4_check_offset) = match ipv4hdr.proto {
        IpProto::Tcp => (
            l4_offset + offset_of!(TcpHdr, source),
            l4_offset + offset_of!(TcpHdr, check),
        ),
        IpProto::Udp => (
            l4_offset + offset_of!(UdpHdr, src),
            l4_offset + offset_of!(UdpHdr, check),
        ),
        _ => return Ok(TC_ACT_PIPE),
    };

    let l4_ip_flags = proto.l4_ip_flags();
    let l4_port_flags = proto.l4_port_flags();
    let proto = proto as u8;

    let rev_nat_key = NodePortRevNatV4Key::new_egress(src_ip, dst_ip, src_port, dst_port, proto);
    let Some(rev_nat_value) = (unsafe { NODEPORT_REV_NAT_V4.get(rev_nat_key).copied() }) else {
        return Ok(TC_ACT_PIPE);
    };

    ctx.l3_csum_replace(
        ipv4_check_offset,
        src_ip.to_be() as u64,
        rev_nat_value.src_ip as u64,
        4,
    )
    .map_err(|_| TC_ACT_PIPE)?;

    ctx.l4_csum_replace(
        l4_check_offset,
        src_port.to_be() as u64,
        rev_nat_value.src_port as u64,
        l4_port_flags,
    )
    .map_err(|_| TC_ACT_PIPE)?;

    ctx.l4_csum_replace(
        l4_check_offset,
        src_ip.to_be() as u64,
        rev_nat_value.src_ip as u64,
        l4_ip_flags,
    )
    .map_err(|_| TC_ACT_PIPE)?;

    ctx.store(src_ip_offset, &rev_nat_value.src_ip, 0)
        .map_err(|_| TC_ACT_PIPE)?;
    ctx.store(src_port_offset, &rev_nat_value.src_port, 0)
        .map_err(|_| TC_ACT_PIPE)?;

    Ok(TC_ACT_PIPE)
}

// TODO: check if this can be combined with KubeProtocol in mesh-cni-ebpf-common
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Protocol {
    Tcp = 6,
    Udp = 17,
    Sctp = 132,
}

impl Protocol {
    pub const fn l4_ip_flags(&self) -> u64 {
        match self {
            Protocol::Tcp => BPF_F_PSEUDO_HDR as u64 | 4,
            Protocol::Udp => BPF_F_PSEUDO_HDR as u64 | BPF_F_MARK_MANGLED_0 as u64 | 4,
            Protocol::Sctp => todo!(),
        }
    }

    pub const fn l4_port_flags(&self) -> u64 {
        match self {
            Protocol::Tcp => 2,
            Protocol::Udp => BPF_F_MARK_MANGLED_0 as u64 | 2,
            Protocol::Sctp => todo!(),
        }
    }
}
