#![no_std]
#![no_main]

use aya_ebpf::{macros::classifier, programs::TcContext};
use homelab_cni_ebpf::egress::try_homelab_cni_egress;
use homelab_cni_ebpf::ingress::try_homelab_cni_ingress;

#[classifier]
pub fn homelab_cni_ingress(ctx: TcContext) -> i32 {
    match try_homelab_cni_ingress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[classifier]
pub fn homelab_cni_egress(ctx: TcContext) -> i32 {
    match try_homelab_cni_egress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
