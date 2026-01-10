#![no_std]
#![no_main]

use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
use mesh_cni_policy_ebpf::ingress::try_mesh_cni_ingress;

#[classifier]
pub fn mesh_cni_ingress(ctx: TcContext) -> i32 {
    match try_mesh_cni_ingress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
