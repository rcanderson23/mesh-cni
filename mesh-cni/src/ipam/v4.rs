use std::net::Ipv4Addr;

use ahash::HashSet;
use anyhow::{self, bail};
use cidr::Ipv4Cidr;

use crate::Result;

pub struct IpamV4 {
    cidr: Ipv4Cidr,
    allocated: HashSet<Ipv4Addr>,
    last_allocated: Option<Ipv4Addr>,
}

impl IpamV4 {
    pub fn try_new(cidr: Ipv4Cidr, allocated: HashSet<Ipv4Addr>) -> Result<Self> {
        if cidr.network_length() > 30 {
            bail!(
                "invalid network length {} provided, must be less than or equal to 30 ",
                cidr.network_length()
            )
        }
        Ok(Self {
            cidr,
            allocated,
            last_allocated: None,
        })
    }
    pub fn allocate_ip(&mut self) -> Result<Ipv4Addr> {
        // first and last IPs are network and broadcast so ignore those
        let first_usable = u32::from(self.cidr.first_address()) + 1;
        let last_usable = u32::from(self.cidr.last_address()) - 1;
        let start = match self.last_allocated {
            Some(ip) => next_ipv4(u32::from(ip), first_usable, last_usable),
            None => first_usable,
        };

        let mut ip = Ipv4Addr::from(start);
        loop {
            if self.allocated.insert(ip) {
                self.last_allocated = Some(ip);
                return Ok(ip);
            }

            let next = next_ipv4(u32::from(ip), first_usable, last_usable);
            if next == start {
                bail!("no usable IPv4 addrs available");
            }
            ip = Ipv4Addr::from(next);
        }
    }

    pub fn release_ip(&mut self, ip: Ipv4Addr) -> Result<()> {
        self.allocated.remove(&ip);

        Ok(())
    }
}

fn next_ipv4(current: u32, first_usable: u32, last_usable: u32) -> u32 {
    if current < first_usable || current >= last_usable {
        first_usable
    } else {
        current + 1
    }
}
