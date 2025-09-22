use aya_ebpf::bindings::bpf_sock_addr;
use aya_ebpf::helpers::r#gen::bpf_get_prandom_u32;
use aya_ebpf::programs::SockAddrContext;
use mesh_cni_ebpf_common::service::{EndpointKey, ServiceKeyV4};

use crate::{ENDPOINTS_V4, SERVICES_V4};

const AF_INET: u16 = 2;
const _AF_INET6: u16 = 10;

// https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/#context
// Example: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/#example
// struct bpf_sock_addr {
//     __u32 user_family;  /* Allows 4-byte read, but no write. */
//     __u32 user_ip4;     /* Allows 1,2,4-byte read and 4-byte write.
//                 * Stored in network byte order.
//                 */
//     __u32 user_ip6[4];  /* Allows 1,2,4,8-byte read and 4,8-byte write.
//                 * Stored in network byte order.
//                 */
//     __u32 user_port;    /* Allows 1,2,4-byte read and 4-byte write.
//                 * Stored in network byte order
//                 */
//     __u32 family;       /* Allows 4-byte read, but no write */
//     __u32 type;     /* Allows 4-byte read, but no write */
//     __u32 protocol;     /* Allows 4-byte read, but no write */
//     __u32 msg_src_ip4;  /* Allows 1,2,4-byte read and 4-byte write.
//                 * Stored in network byte order.
//                 */
//     __u32 msg_src_ip6[4];   /* Allows 1,2,4,8-byte read and 4,8-byte write.
//                 * Stored in network byte order.
//                 */
//     __bpf_md_ptr(struct bpf_sock *, sk);
// };
//
//

///
/// Return codes [0(deny),1(allow)]
#[inline]
pub fn try_mesh_cni_group_connect4(ctx: SockAddrContext) -> Result<i32, i32> {
    let ptr = ctx.sock_addr;

    if unsafe { *ptr }.user_family != AF_INET as u32 {
        return Ok(1);
    };

    let service_key = build_service_key(&ctx, ptr)?;
    let service_value = unsafe {
        match SERVICES_V4.get(&service_key) {
            Some(value) => value,
            None => return Ok(1),
        }
    };
    if service_value.count == 0 {
        return Err(0);
    }
    let position = get_position(service_value.count);

    let endpoints_value = unsafe {
        match ENDPOINTS_V4.get(&EndpointKey {
            id: service_value.id,
            position,
        }) {
            Some(value) => value,
            None => return Ok(1),
        }
    };

    unsafe {
        (*ptr).user_ip4 = endpoints_value.ip.to_be();
        (*ptr).user_port = endpoints_value.port.to_be() as u32;
    }

    Ok(1)
}

#[inline]
fn build_service_key(_ctx: &SockAddrContext, ptr: *mut bpf_sock_addr) -> Result<ServiceKeyV4, i32> {
    let (ip, port, protocol) = unsafe {
        let ip = u32::from_be((*ptr).user_ip4);
        let port = u16::from_be((*ptr).user_port as u16);
        let protocol = (*ptr).protocol.try_into().map_err(|_| 1)?;
        (ip, port, protocol)
    };

    Ok(ServiceKeyV4 { ip, port, protocol })
}

#[inline]
fn get_random() -> u32 {
    unsafe { bpf_get_prandom_u32() }
}

#[inline]
fn get_position(count: u16) -> u16 {
    let rand = get_random() as u16;
    rand % count
}
