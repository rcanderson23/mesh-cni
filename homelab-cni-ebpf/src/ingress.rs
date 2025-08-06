use aya_ebpf::{bindings::TC_ACT_PIPE, programs::TcContext};
use aya_log_ebpf::info;

pub fn try_homelab_cni_ingress(ctx: TcContext) -> Result<i32, i32> {
    Ok(TC_ACT_PIPE)
}
