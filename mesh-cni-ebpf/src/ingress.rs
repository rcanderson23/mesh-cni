use aya_ebpf::cty::c_long;
use aya_ebpf::programs::SkBuffContext;
use aya_ebpf::{bindings::TC_ACT_PIPE, programs::TcContext};
use aya_log_ebpf::{error, info};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::Ipv4Hdr;
use network_types::tcp::TcpHdr;

use crate::{IP_IDENTITY, ip_id};

static SYN_BIT: usize = 31;

#[inline]
pub fn try_mesh_cni_ingress(ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;

    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| TC_ACT_PIPE)?;

    let src = u32::from_be_bytes(ipv4hdr.src_addr);
    let dst = u32::from_be_bytes(ipv4hdr.dst_addr);

    let (Some(src_id), Some(dst_id)) = (ip_id(src.into()), ip_id(dst.into())) else {
        return Ok(TC_ACT_PIPE);
    };

    // requests on the same node do not got through eth0 so we need to attach elsewhere
    // likely the cgroup path so we will need to determine those based on the pods present
    info!(&ctx, "getting tcphdr");
    let tcphdr: Result<TcpHdr, c_long> = match ipv4hdr.proto {
        network_types::ip::IpProto::Tcp => ctx.load(EthHdr::LEN + Ipv4Hdr::LEN),
        network_types::ip::IpProto::Ipv4 => {
            info!(&ctx, "found ipv4 proto");
            return Ok(TC_ACT_PIPE);
        }
        network_types::ip::IpProto::Ipv6 => {
            info!(&ctx, "found ipv6 proto");
            return Ok(TC_ACT_PIPE);
        }
        network_types::ip::IpProto::Udp => {
            info!(&ctx, "found udp proto");
            return Ok(TC_ACT_PIPE);
        }
        _ => {
            info!(&ctx, "proto found unexpected: {}", ipv4hdr.proto as u8);
            return Ok(TC_ACT_PIPE);
        }
    };
    let tcphdr = match tcphdr {
        Ok(t) => t,
        Err(e) => {
            error!(&ctx, "failed to load tcphdr: {}", e);
            return Ok(TC_ACT_PIPE);
        }
    };

    info!(&ctx, "loading bitfield");
    let bitfield = tcphdr._bitfield_1;
    for bit in 8..15 {
        if bitfield.get_bit(bit) {
            info!(
                &ctx,
                "bit {} set, src_id: {}, dst_id: {}", bit, src_id, dst_id
            );
        }
    }
    // let syn = bitfield.get_bit(SYN_BIT);
    // let ack = bitfield.get_bit(15);

    // if syn {
    // } else {
    // }
    // ipv4hdr.tot_len

    Ok(TC_ACT_PIPE)
}
