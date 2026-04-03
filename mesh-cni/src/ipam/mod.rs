mod node;
mod noop;
mod v4;

use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use anyhow::bail;
pub use node::get_ipamv4_from_node;
pub use noop::NoopIpam;
pub use v4::IpamV4;

use crate::{Result, http};

pub enum Ipam {
    V4(IpamV4),
    Noop(NoopIpam),
}

impl http::grpc::cni::Ipam for Arc<Mutex<Ipam>> {
    fn first_v4(&self) -> Result<Ipv4Addr> {
        let mut guard = self.lock().unwrap();
        match *guard {
            Ipam::V4(ref mut ipam_v4) => ipam_v4.first_address(),
            Ipam::Noop(_) => bail!("first_v4 not implemented for noop"),
        }
    }
    fn allocate_v4_ip(&self) -> Result<Ipv4Addr> {
        let mut guard = self.lock().unwrap();
        match *guard {
            Ipam::V4(ref mut ipam_v4) => ipam_v4.allocate_ip(),
            Ipam::Noop(_) => bail!("allocate_v4_ip not implemented for noop"),
        }
    }

    fn release_v4_ip(&self, ip: Ipv4Addr) -> Result<()> {
        let mut guard = self.lock().unwrap();
        match *guard {
            Ipam::V4(ref mut ipam_v4) => ipam_v4.release_ip(ip),
            Ipam::Noop(_) => Ok(()),
        }
    }

    fn network_length_v4(&self) -> u8 {
        let guard = self.lock().unwrap();

        match &*guard {
            Ipam::V4(ipam_v4) => ipam_v4.cidr(),
            Ipam::Noop(_) => unimplemented!("network_length_v4 not implemented for noop ipam"),
        }
    }
}
