use aya_ebpf::{bindings::TC_ACT_PIPE, programs::TcContext};
use network_types::eth::{EthHdr, EtherType};

use crate::ipv4::handle_ipv4;

#[inline]
pub fn try_mesh_cni_ingress(ctx: TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;

    let Ok(ether_type) = ethhdr.ether_type() else {
        return Ok(TC_ACT_PIPE);
    };

    if !matches!(ether_type, EtherType::Ipv4) {
        return Ok(TC_ACT_PIPE);
    }

    handle_ipv4(ctx)
}
