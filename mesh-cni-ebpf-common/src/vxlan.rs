pub const VXLAN_IFINDEX_SLOT: u32 = 0;

/// Stores information for VXLAN forwarding. Values are stored in host order.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RemoteNodeV4 {
    /// Ip of the node hosting the pod cidr. Should be stored in host order
    pub ip: u32,
    /// The vni of the vxlan. Only valid value currently is 1.
    pub vni: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RemoteNodeV4 {}
