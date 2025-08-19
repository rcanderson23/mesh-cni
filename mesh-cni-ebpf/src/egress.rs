use aya_ebpf::{bindings::TC_ACT_PIPE, programs::TcContext};

pub fn try_mesh_cni_egress(ctx: TcContext) -> Result<i32, i32> {
    Ok(TC_ACT_PIPE)
}
