use aya_ebpf::{
    bindings::TC_ACT_PIPE, cty::c_long, maps::lpm_trie::Key as LpmKey, programs::TcContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
};

use crate::id_v4;

#[inline]
pub fn handle_ipv4(ctx: TcContext) -> Result<i32, i32> {
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| TC_ACT_PIPE)?;

    let src = u32::from_be_bytes(ipv4hdr.src_addr);
    let dst = u32::from_be_bytes(ipv4hdr.dst_addr);

    // LpmTrie expects big endian order for comparisons
    let (Some(src_id), Some(dst_id)) = (
        id_v4(LpmKey::new(32, src.to_be())),
        id_v4(LpmKey::new(32, dst.to_be())),
    ) else {
        return Ok(TC_ACT_PIPE);
    };

    let tcphdr: TcpHdr = match ipv4hdr.proto {
        network_types::ip::IpProto::Tcp => ctx
            .load(EthHdr::LEN + Ipv4Hdr::LEN)
            .map_err(|_| TC_ACT_PIPE)?,
        network_types::ip::IpProto::Udp => return Ok(TC_ACT_PIPE),
        _ => {
            info!(&ctx, "proto found unexpected: {}", ipv4hdr.proto as u8);
            return Ok(TC_ACT_PIPE);
        }
    };

    let src_port = u16::from_be_bytes(tcphdr.source);
    let dst_port = u16::from_be_bytes(tcphdr.dest);

    info!(
        &ctx,
        "TCP: src: {}:{}; dst: {}:{}", src_id, src_port, dst_id, dst_port
    );

    Ok(TC_ACT_PIPE)
}
