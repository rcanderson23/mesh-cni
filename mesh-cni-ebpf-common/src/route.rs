use core::net::Ipv4Addr;

#[repr(u8)]
pub enum RouteType {
    LocalPod = 1,
    RemotePod = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub struct RouteV4 {
    pub route_type: u8,
    pub _pad: [u8; 3],
    pub ifindex: u32,
    pub remote_ip: u32,
    pub vni: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RouteV4 {}

impl RouteV4 {
    /// The provided ifindex should be host side interface connected to the pod interface
    pub fn new_local(ifindex: u32) -> Self {
        Self {
            route_type: RouteType::LocalPod as u8,
            _pad: [0; 3],
            ifindex,
            remote_ip: 0,
            vni: 0,
        }
    }

    /// The ifindex should point to the vxlan interface to use to route to the remote IP
    pub fn new_remote(ifindex: u32, remote_ip: Ipv4Addr, vni: u32) -> Self {
        Self {
            route_type: RouteType::RemotePod as u8,
            _pad: [0; 3],
            ifindex,
            remote_ip: remote_ip.to_bits(),
            vni,
        }
    }
}
