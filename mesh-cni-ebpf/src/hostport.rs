use core::mem::offset_of;

use aya_ebpf::{
    bindings::tcx_action_base::{TCX_DROP, TCX_NEXT},
    helpers::generated::{bpf_ktime_get_ns, bpf_redirect_peer},
    programs::TcContext,
};
use aya_log_ebpf::error;
use mesh_cni_ebpf_common::{
    KubeProtocol,
    conntrack::{NodePortConntrackV4Key, NodePortConntrackV4Value, TcpFlags, TcpState},
    hostport::HostPortKeyV4,
    service::{NodePortRevNatV4Key, NodePortRevNatV4Value},
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::{
    HOSTPORT_V4, IFINDEX_V4, NODEPORT_CONNTRACK_V4, NODEPORT_LOCAL_ADDRS_V4, NODEPORT_REV_NAT_V4,
    service::{ProtocolExt, is_nodeport_conntrack_expired},
};

// TODO: implement ipv6
// TODO: consider sctp?
#[inline]
pub fn try_mesh_cni_hostport_ingress(mut ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TCX_NEXT)?;
    let Ok(ether_type) = ethhdr.ether_type() else {
        return Ok(TCX_NEXT);
    };
    if !matches!(ether_type, EtherType::Ipv4) {
        return Ok(TCX_NEXT);
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| TCX_NEXT)?;
    let ihl = ipv4hdr.ihl();
    let orig_dst_ip = u32::from_be_bytes(ipv4hdr.dst_addr);

    // pass traffic that isn't pointed at IPs assigned to attached ifaces
    // as this could meant for pods
    if unsafe { NODEPORT_LOCAL_ADDRS_V4.get(orig_dst_ip) }.is_none() {
        return Ok(TCX_NEXT);
    }

    let (orig_dst_port, src_port, proto, tcp_flags) = match ipv4hdr.proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = ctx.load(EthHdr::LEN + ihl as usize).map_err(|_| TCX_NEXT)?;
            let syn = tcphdr.syn() == 1;
            let ack = tcphdr.ack() == 1;
            let fin = tcphdr.fin() == 1;
            let rst = tcphdr.rst() == 1;
            (
                u16::from_be_bytes(tcphdr.dest),
                u16::from_be_bytes(tcphdr.source),
                KubeProtocol::Tcp,
                Some(TcpFlags::new(syn, ack, fin, rst)),
            )
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = ctx.load(EthHdr::LEN + ihl as usize).map_err(|_| TCX_NEXT)?;
            (
                u16::from_be_bytes(udphdr.dst),
                u16::from_be_bytes(udphdr.src),
                KubeProtocol::Udp,
                None,
            )
        }
        _ => return Ok(TCX_NEXT),
    };

    let wildcard_key = HostPortKeyV4::new(0, orig_dst_port, proto as u8);
    let exact_key = HostPortKeyV4::new(orig_dst_ip, orig_dst_port, proto as u8);
    let hostport_value = unsafe {
        match (
            HOSTPORT_V4.get(wildcard_key).copied(),
            HOSTPORT_V4.get(exact_key).copied(),
        ) {
            (None, None) => return Ok(TCX_NEXT),
            // exact match wins if we somehow have wildcard and exact match but this should not
            // happen
            (Some(wildcard_value), None) => wildcard_value,
            (Some(_), Some(exact_value)) => exact_value,
            (_, Some(exact_value)) => exact_value,
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
        _ => return Ok(TCX_NEXT),
    };

    let src_ip = u32::from_be_bytes(ipv4hdr.src_addr);
    let desired_dst_ip = hostport_value.ip.to_be();
    let desired_dst_port = hostport_value.port.to_be();
    let mut new_dst_ip = desired_dst_ip;
    let mut new_dst_port = desired_dst_port;
    let l4_ip_flags = proto.l4_ip_flags();
    let l4_port_flags = proto.l4_port_flags();
    let proto_u8 = proto as u8;
    let now = unsafe { bpf_ktime_get_ns() };
    let conntrack_key =
        NodePortConntrackV4Key::new(src_ip, orig_dst_ip, src_port, orig_dst_port, proto_u8);
    let mut current_state = TcpState::None;
    if let Some(value) = unsafe { NODEPORT_CONNTRACK_V4.get(conntrack_key).copied() } {
        if is_nodeport_conntrack_expired(value, now, proto_u8)
            || value.dst_ip != desired_dst_ip
            || value.dst_port != desired_dst_port
        {
            let _ = NODEPORT_CONNTRACK_V4.remove(conntrack_key);
            let rev_nat_key = NodePortRevNatV4Key::new_egress(
                u32::from_be(value.dst_ip),
                src_ip,
                u16::from_be(value.dst_port),
                src_port,
                proto as u8,
            );
            let _ = NODEPORT_REV_NAT_V4.remove(rev_nat_key);
        } else {
            new_dst_ip = value.dst_ip;
            new_dst_port = value.dst_port;
            current_state = value.tcp_state();
        }
    }
    let Some(ifindex) = (unsafe { IFINDEX_V4.get(u32::from_be(new_dst_ip)).copied() }) else {
        return Ok(TCX_NEXT);
    };

    let next_state = current_state.advance(TcpState::from_packet(proto, tcp_flags, false));
    let conntrack_value =
        NodePortConntrackV4Value::new(new_dst_ip, new_dst_port, proto_u8, next_state, now);
    NODEPORT_CONNTRACK_V4
        .insert(conntrack_key, conntrack_value, 0)
        .map_err(|_| TCX_DROP)?;

    // Reverse-NAT keys must match reply traffic tuple seen on mesh_pod ingress:
    // backend_ip:backend_port -> client_ip:client_port.
    let rev_nat_key = NodePortRevNatV4Key::new_egress(
        u32::from_be(new_dst_ip),
        src_ip,
        u16::from_be(new_dst_port),
        src_port,
        proto_u8,
    );
    if unsafe { NODEPORT_REV_NAT_V4.get(rev_nat_key) }.is_none() {
        let rev_nat_value =
            NodePortRevNatV4Value::new(orig_dst_ip.to_be(), orig_dst_port.to_be(), proto_u8);
        NODEPORT_REV_NAT_V4
            .insert(rev_nat_key, rev_nat_value, 0)
            .map_err(|_| {
                error!(&ctx, "failed to insert rev nat key");
                TCX_DROP
            })?;
    }

    ctx.l3_csum_replace(
        ipv4_check_offset,
        orig_dst_ip.to_be() as u64,
        new_dst_ip as u64,
        4,
    )
    .map_err(|_| TCX_DROP)?;

    ctx.l4_csum_replace(
        l4_check_offset,
        orig_dst_port.to_be() as u64,
        new_dst_port as u64,
        l4_port_flags,
    )
    .map_err(|_| TCX_DROP)?;

    ctx.l4_csum_replace(
        l4_check_offset,
        orig_dst_ip.to_be() as u64,
        new_dst_ip as u64,
        l4_ip_flags,
    )
    .map_err(|_| TCX_DROP)?;

    ctx.store(dst_ip_offset, &new_dst_ip, 0)
        .map_err(|_| TCX_DROP)?;
    ctx.store(dst_port_offset, &new_dst_port, 0)
        .map_err(|_| TCX_DROP)?;

    let rc = unsafe { bpf_redirect_peer(ifindex, 0) };
    if rc < 0 {
        error!(&ctx, "failed to redirect hostport packet, got {}", rc);
        return Err(TCX_DROP);
    }

    Ok(rc as i32)
}
