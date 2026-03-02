use core::{mem::offset_of, net::Ipv4Addr};

use aya_ebpf::{
    bindings::{BPF_F_MARK_MANGLED_0, BPF_F_PSEUDO_HDR, TC_ACT_PIPE, bpf_sock_addr},
    helpers::generated::bpf_get_prandom_u32,
    programs::{SockAddrContext, TcContext},
};
use aya_log_ebpf::debug;
use mesh_cni_ebpf_common::service::{
    EndpointKey, NODEPORT_FRONTEND_F_SNAT, NODEPORT_NAT_REWRITE_DST, NODEPORT_NAT_REWRITE_SRC,
    NodePortKey, NodePortNatV4Key, NodePortNatV4Value, ServiceKeyV4,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::{ENDPOINTS_V4, NODEPORT_NAT_V4, NODEPORT_POLICIES_V4, NODEPORTS_V4, SERVICES_V4};

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
                debug!(&ctx, "did not find value for service key");
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
fn build_service_key(ctx: &SockAddrContext, ptr: *mut bpf_sock_addr) -> Result<ServiceKeyV4, i32> {
    let (ip, port, protocol) = unsafe {
        let ip = u32::from_be((*ptr).user_ip4);
        let port = u16::from_be((*ptr).user_port as u16);
        let protocol = (*ptr).protocol.try_into().map_err(|_| 1)?;
        debug!(ctx, "built service key {}:{}", Ipv4Addr::from(ip), port,);
        (ip, port, protocol)
    };

    Ok(ServiceKeyV4::new(ip, port, protocol))
}

#[inline]
fn get_position(count: u16) -> u16 {
    let rand = unsafe { bpf_get_prandom_u32() as u16 };
    rand % count
}

#[inline]
pub fn try_mesh_cni_nodeport_ingress(ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;
    let Ok(ether_type) = ethhdr.ether_type() else {
        return Ok(TC_ACT_PIPE);
    };

    // TODO: handle IPv6
    if !matches!(ether_type, EtherType::Ipv4) {
        return Ok(TC_ACT_PIPE);
    }

    handle_nodeport_ingress_ipv4(ctx)
}

#[inline]
pub fn try_mesh_cni_nodeport_egress(ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;
    let Ok(ether_type) = ethhdr.ether_type() else {
        return Ok(TC_ACT_PIPE);
    };

    // TODO: handle IPv6
    if !matches!(ether_type, EtherType::Ipv4) {
        return Ok(TC_ACT_PIPE);
    }

    handle_nodeport_egress_ipv4(ctx)
}

#[inline]
fn handle_nodeport_egress_ipv4(mut ctx: TcContext) -> Result<i32, i32> {
    let packet = parse_nodeport_ipv4_packet(&ctx)?;

    let nat_key = NodePortNatV4Key::new(
        packet.src_ip,
        packet.dst_ip,
        packet.l4.src_port,
        packet.l4.dst_port,
        packet.protocol_u8,
    );
    if let Some(nat_value) = unsafe { NODEPORT_NAT_V4.get(nat_key).copied() } {
        apply_nodeport_nat_v4(&mut ctx, &packet, nat_value)?;
    }
    Ok(TC_ACT_PIPE)
}

#[inline]
fn handle_nodeport_ingress_ipv4(mut ctx: TcContext) -> Result<i32, i32> {
    let packet = parse_nodeport_ipv4_packet(&ctx)?;
    let nat_key = NodePortNatV4Key::new(
        packet.src_ip,
        packet.dst_ip,
        packet.l4.src_port,
        packet.l4.dst_port,
        packet.protocol_u8,
    );
    if let Some(nat_value) = unsafe { NODEPORT_NAT_V4.get(nat_key).copied() } {
        apply_nodeport_nat_v4(&mut ctx, &packet, nat_value)?;
        return Ok(TC_ACT_PIPE);
    }

    let nodeport_key = NodePortKey::new(packet.l4.dst_port, packet.protocol_u8);
    let should_snat = unsafe {
        NODEPORT_POLICIES_V4
            .get(nodeport_key)
            .map(|meta| (meta.flags & NODEPORT_FRONTEND_F_SNAT) != 0)
            .unwrap_or(false)
    };
    let service_key = unsafe {
        match NODEPORTS_V4.get(nodeport_key).copied() {
            Some(key) => key,
            None => return Ok(TC_ACT_PIPE),
        }
    };
    let service_value = unsafe {
        match SERVICES_V4.get(service_key).copied() {
            Some(value) => value,
            None => return Ok(TC_ACT_PIPE),
        }
    };
    if service_value.count == 0 {
        return Ok(TC_ACT_PIPE);
    }

    let forward_nat_value = unsafe {
        let position = get_position(service_value.count);
        let endpoint_key = EndpointKey::new(service_value.id, position);
        let endpoint = match ENDPOINTS_V4.get(endpoint_key).copied() {
            Some(value) => value,
            None => return Ok(TC_ACT_PIPE),
        };

        // Forward mapping preserves backend affinity and applies DNAT (+ optional SNAT).
        let forward_value = if should_snat {
            NodePortNatV4Value::new_src_dst(
                packet.dst_ip,
                packet.l4.src_port,
                endpoint.ip,
                endpoint.port,
            )
        } else {
            NodePortNatV4Value::new_dst(endpoint.ip, endpoint.port)
        };
        let _ = NODEPORT_NAT_V4.insert(nat_key, forward_value, 0);

        // Reverse mapping rewrites backend replies back to nodeport frontend + original client tuple.
        let reverse_key = NodePortNatV4Key::new(
            endpoint.ip,
            packet.dst_ip,
            endpoint.port,
            packet.l4.src_port,
            packet.protocol_u8,
        );
        let reverse_value = if should_snat {
            NodePortNatV4Value::new_src_dst(
                packet.dst_ip,
                packet.l4.dst_port,
                packet.src_ip,
                packet.l4.src_port,
            )
        } else {
            NodePortNatV4Value::new_src(packet.dst_ip, packet.l4.dst_port)
        };
        let _ = NODEPORT_NAT_V4.insert(reverse_key, reverse_value, 0);

        // Keep compatibility for direct backend->client return paths that hit tc egress.
        let legacy_reverse_key = NodePortNatV4Key::new(
            endpoint.ip,
            packet.src_ip,
            endpoint.port,
            packet.l4.src_port,
            packet.protocol_u8,
        );
        let legacy_reverse_value = NodePortNatV4Value::new_src(packet.dst_ip, packet.l4.dst_port);
        let _ = NODEPORT_NAT_V4.insert(legacy_reverse_key, legacy_reverse_value, 0);

        forward_value
    };
    apply_nodeport_nat_v4(&mut ctx, &packet, forward_nat_value)?;

    Ok(TC_ACT_PIPE)
}

#[inline]
fn apply_nodeport_nat_v4(
    ctx: &mut TcContext,
    packet: &NodePortPacketV4,
    nat_value: NodePortNatV4Value,
) -> Result<(), i32> {
    let ipv4_check_offset = packet.ipv4_offset + offset_of!(Ipv4Hdr, check);

    if (nat_value.flags & NODEPORT_NAT_REWRITE_SRC) != 0 {
        let new_src_ip = nat_value.src_ip.to_be_bytes();
        let new_src_ip_raw = u32::from_ne_bytes(new_src_ip);
        let new_src_port = nat_value.src_port.to_be_bytes();
        let new_src_port_raw = u16::from_ne_bytes(new_src_port);

        if packet.old_src_ip_raw != new_src_ip_raw {
            ctx.l3_csum_replace(
                ipv4_check_offset,
                packet.old_src_ip_raw as u64,
                new_src_ip_raw as u64,
                4,
            )
            .map_err(|_| TC_ACT_PIPE)?;

            ctx.l4_csum_replace(
                packet.l4.check_offset,
                packet.old_src_ip_raw as u64,
                new_src_ip_raw as u64,
                l4_ip_flags(packet.l4.transport),
            )
            .map_err(|_| TC_ACT_PIPE)?;

            let src_ip_offset = packet.ipv4_offset + offset_of!(Ipv4Hdr, src_addr);
            ctx.store(src_ip_offset, &new_src_ip, 0)
                .map_err(|_| TC_ACT_PIPE)?;
        }

        if packet.l4.src_port_raw != new_src_port_raw {
            ctx.l4_csum_replace(
                packet.l4.check_offset,
                packet.l4.src_port_raw as u64,
                new_src_port_raw as u64,
                l4_port_flags(packet.l4.transport),
            )
            .map_err(|_| TC_ACT_PIPE)?;

            ctx.store(packet.l4.src_port_offset, &new_src_port, 0)
                .map_err(|_| TC_ACT_PIPE)?;
        }
    }

    if (nat_value.flags & NODEPORT_NAT_REWRITE_DST) != 0 {
        let new_dst_ip = nat_value.dst_ip.to_be_bytes();
        let new_dst_ip_raw = u32::from_ne_bytes(new_dst_ip);
        let new_dst_port = nat_value.dst_port.to_be_bytes();
        let new_dst_port_raw = u16::from_ne_bytes(new_dst_port);

        if packet.old_dst_ip_raw != new_dst_ip_raw {
            ctx.l3_csum_replace(
                ipv4_check_offset,
                packet.old_dst_ip_raw as u64,
                new_dst_ip_raw as u64,
                4,
            )
            .map_err(|_| TC_ACT_PIPE)?;

            ctx.l4_csum_replace(
                packet.l4.check_offset,
                packet.old_dst_ip_raw as u64,
                new_dst_ip_raw as u64,
                l4_ip_flags(packet.l4.transport),
            )
            .map_err(|_| TC_ACT_PIPE)?;

            let dst_ip_offset = packet.ipv4_offset + offset_of!(Ipv4Hdr, dst_addr);
            ctx.store(dst_ip_offset, &new_dst_ip, 0)
                .map_err(|_| TC_ACT_PIPE)?;
        }

        if packet.l4.dst_port_raw != new_dst_port_raw {
            ctx.l4_csum_replace(
                packet.l4.check_offset,
                packet.l4.dst_port_raw as u64,
                new_dst_port_raw as u64,
                l4_port_flags(packet.l4.transport),
            )
            .map_err(|_| TC_ACT_PIPE)?;

            ctx.store(packet.l4.dst_port_offset, &new_dst_port, 0)
                .map_err(|_| TC_ACT_PIPE)?;
        }
    }

    Ok(())
}

struct NodePortPacketV4 {
    ipv4_offset: usize,
    protocol_u8: u8,
    src_ip: u32,
    dst_ip: u32,
    old_src_ip_raw: u32,
    old_dst_ip_raw: u32,
    l4: L4State,
}

#[inline]
fn parse_nodeport_ipv4_packet(ctx: &TcContext) -> Result<NodePortPacketV4, i32> {
    let ipv4_offset = EthHdr::LEN;
    let ipv4hdr: Ipv4Hdr = ctx.load(ipv4_offset).map_err(|_| TC_ACT_PIPE)?;
    let ihl = ipv4hdr.ihl() as usize;
    let is_fragmented = ipv4hdr.frag_offset() != 0 || (ipv4hdr.frag_flags() & 0x1) != 0;
    if ihl < Ipv4Hdr::LEN || is_fragmented {
        return Err(TC_ACT_PIPE);
    }
    let l4_offset = ipv4_offset + ihl;

    Ok(NodePortPacketV4 {
        ipv4_offset,
        protocol_u8: ipv4hdr.proto as u8,
        src_ip: u32::from_be_bytes(ipv4hdr.src_addr),
        dst_ip: u32::from_be_bytes(ipv4hdr.dst_addr),
        old_src_ip_raw: u32::from_ne_bytes(ipv4hdr.src_addr),
        old_dst_ip_raw: u32::from_ne_bytes(ipv4hdr.dst_addr),
        l4: parse_l4_state(ctx, l4_offset, ipv4hdr.proto)?,
    })
}

#[derive(Clone, Copy)]
enum Transport {
    Tcp,
    Udp,
}

struct L4State {
    transport: Transport,
    src_port: u16,
    dst_port: u16,
    src_port_raw: u16,
    dst_port_raw: u16,
    src_port_offset: usize,
    dst_port_offset: usize,
    check_offset: usize,
}

fn parse_l4_state(ctx: &TcContext, l4_offset: usize, protocol: IpProto) -> Result<L4State, i32> {
    match protocol {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = ctx.load(l4_offset).map_err(|_| TC_ACT_PIPE)?;
            Ok(L4State {
                transport: Transport::Tcp,
                src_port: u16::from_be_bytes(tcphdr.source),
                dst_port: u16::from_be_bytes(tcphdr.dest),
                src_port_raw: u16::from_ne_bytes(tcphdr.source),
                dst_port_raw: u16::from_ne_bytes(tcphdr.dest),
                src_port_offset: l4_offset + offset_of!(TcpHdr, source),
                dst_port_offset: l4_offset + offset_of!(TcpHdr, dest),
                check_offset: l4_offset + offset_of!(TcpHdr, check),
            })
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = ctx.load(l4_offset).map_err(|_| TC_ACT_PIPE)?;
            Ok(L4State {
                transport: Transport::Udp,
                src_port: u16::from_be_bytes(udphdr.src),
                dst_port: u16::from_be_bytes(udphdr.dst),
                src_port_raw: u16::from_ne_bytes(udphdr.src),
                dst_port_raw: u16::from_ne_bytes(udphdr.dst),
                src_port_offset: l4_offset + offset_of!(UdpHdr, src),
                dst_port_offset: l4_offset + offset_of!(UdpHdr, dst),
                check_offset: l4_offset + offset_of!(UdpHdr, check),
            })
        }
        _ => Err(TC_ACT_PIPE),
    }
}

const fn l4_ip_flags(transport: Transport) -> u64 {
    match transport {
        Transport::Tcp => BPF_F_PSEUDO_HDR as u64 | 4,
        Transport::Udp => BPF_F_PSEUDO_HDR as u64 | BPF_F_MARK_MANGLED_0 as u64 | 4,
    }
}

const fn l4_port_flags(transport: Transport) -> u64 {
    match transport {
        Transport::Tcp => 2,
        Transport::Udp => BPF_F_MARK_MANGLED_0 as u64 | 2,
    }
}
