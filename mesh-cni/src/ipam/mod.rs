mod node;
mod v4;

use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

pub use node::get_ipam_from_node;

use crate::{Result, http};

pub struct Ipam {
    v4: v4::IpamV4,
}

impl http::grpc::cni::Ipam for Arc<Mutex<Ipam>> {
    fn allocate_v4_ip(&self) -> Result<Ipv4Addr> {
        let mut guard = self.lock().unwrap();
        guard.v4.allocate_ip()
    }

    fn release_v4_ip(&self, ip: Ipv4Addr) -> Result<()> {
        let mut guard = self.lock().unwrap();
        guard.v4.release_ip(ip)
    }
}
