#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_sock_addr, classifier},
    programs::{SockAddrContext, TcContext},
};
use mesh_cni_ebpf::{
    egress::try_mesh_cni_egress,
    ingress::try_mesh_cni_ingress,
    service::{try_mesh_cni_cgroup_connect4, try_mesh_cni_nodeport_ingress},
};

#[cgroup_sock_addr(connect4)]
pub fn mesh_cni_cgroup_connect4(ctx: SockAddrContext) -> i32 {
    match try_mesh_cni_cgroup_connect4(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[classifier]
pub fn mesh_cni_ingress(ctx: TcContext) -> i32 {
    match try_mesh_cni_ingress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[classifier]
pub fn mesh_cni_egress(ctx: TcContext) -> i32 {
    match try_mesh_cni_egress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[classifier]
pub fn mesh_cni_nodeport_ingress(ctx: TcContext) -> i32 {
    match try_mesh_cni_nodeport_ingress(ctx) {
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
