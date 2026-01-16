#![no_std]
#![no_main]

use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
use mesh_cni_service_ebpf::service::try_mesh_cni_cgroup_connect4;

#[cgroup_sock_addr(connect4)]
pub fn mesh_cni_cgroup_connect4(ctx: SockAddrContext) -> i32 {
    match try_mesh_cni_cgroup_connect4(ctx) {
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
