use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZero;
use std::os::fd::RawFd;

use ipnetwork::IpNetwork;
use regex::Regex;
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage};
use rtnetlink::packet_route::route::{RouteHeader, RouteMetric, RouteScope};
use rtnetlink::{Handle, packet_route::link::LinkAttribute};
use rtnetlink::{LinkDummy, LinkUnspec, LinkVeth, LinkVxlan, RouteMessageBuilder};
use tokio_stream::StreamExt;

use crate::{Error, Result};

#[derive(Clone, Debug)]
pub struct Netlink {
    handle: Handle,
}

impl Netlink {
    pub fn try_new() -> Result<Self> {
        let (conn, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(conn);
        Ok(Self { handle })
    }

    pub async fn get_link_index_by_name(&self, iface: &str) -> Result<u32> {
        let link = self
            .handle
            .link()
            .get()
            .match_name(iface.to_string())
            .execute()
            .try_next()
            .await?
            .ok_or_else(|| Error::NotFound(format!("interface {iface}")))?;

        Ok(link.header.index)
    }

    /// Returns the peer ifindex for a given interface name.
    pub async fn get_peer_ifindex_by_name(&self, iface: &str) -> Result<u32> {
        let link = self
            .handle
            .link()
            .get()
            .match_name(iface.to_string())
            .execute()
            .try_next()
            .await?
            .ok_or_else(|| Error::NotFound(format!("interface {iface}")))?;

        for attr in link.attributes {
            if let LinkAttribute::Link(peer_ifindex) = attr {
                return Ok(peer_ifindex);
            }
        }

        Err(Error::NotFound(format!(
            "peer ifindex for interface {iface}"
        )))
    }

    pub async fn find_first_iface_match(&self, iface_regex: &Regex) -> Result<String> {
        let mut links = self.handle.link().get().execute();
        while let Some(link) = links.try_next().await? {
            for attr in &link.attributes {
                if let rtnetlink::packet_route::link::LinkAttribute::IfName(name) = attr
                    && iface_regex.is_match(name)
                {
                    return Ok(name.clone());
                }
            }
        }
        Err(Error::NotFound(format!(
            "interface matching regex {iface_regex}"
        )))
    }

    /// Returns the MTU of a given interface by name
    pub async fn get_mtu_from_iface(&self, name: &str) -> Result<u32> {
        let link = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute()
            .try_next()
            .await?
            .ok_or_else(|| Error::NotFound(format!("interface {name}")))?;

        for attr in link.attributes {
            if let LinkAttribute::Mtu(mtu) = attr {
                return Ok(mtu);
            }
        }
        Err(Error::NotFound(format!("failed to find MTU on {name}")))
    }

    /// Ensures the dummy interface exists
    pub async fn ensure_dummy_iface(&self, iface: &str) -> Result<u32> {
        match self
            .handle
            .link()
            .get()
            .match_name(iface.to_string())
            .execute()
            .try_next()
            .await
        {
            Ok(Some(l)) => {
                return Ok(l.header.index);
            }
            // attempt to create here although I don't know the circumstances where
            // this will happen as it appears we get an error if we try to fetch an interface that
            // doesn't exist
            Ok(None) => {}
            Err(rtnetlink::Error::NetlinkError(m))
                if m.code == Some(NonZero::new(-libc::ENODEV).unwrap()) => {}
            Err(e) => return Err(e.into()),
        }

        self.handle
            .link()
            .add(LinkDummy::new(iface).up().build())
            .execute()
            .await?;

        self.get_link_index_by_name(iface).await
    }

    /// Ensures routes to a given ifindex with a specified MTU
    pub async fn ensure_route(&self, routes: &[IpNetwork], ifindex: u32, mtu: u32) -> Result<()> {
        for route in routes {
            match route {
                IpNetwork::V4(network) => {
                    let mut msg = RouteMessageBuilder::<Ipv4Addr>::new()
                        .destination_prefix(network.ip(), network.prefix())
                        .output_interface(ifindex)
                        .build();

                    msg.attributes
                        .push(rtnetlink::packet_route::route::RouteAttribute::Metrics(
                            vec![RouteMetric::Mtu(mtu)],
                        ));
                    self.handle.route().add(msg).replace().execute().await?;
                }
                IpNetwork::V6(network) => {
                    let mut msg = RouteMessageBuilder::<Ipv6Addr>::new()
                        .destination_prefix(network.ip(), network.prefix())
                        .output_interface(ifindex)
                        .build();

                    msg.attributes
                        .push(rtnetlink::packet_route::route::RouteAttribute::Metrics(
                            vec![RouteMetric::Mtu(mtu)],
                        ));
                    self.handle.route().add(msg).replace().execute().await?;
                }
            }
        }

        Ok(())
    }

    /// Enusres the vxlan interface is created and returns its ifindex
    pub async fn ensure_vxlan_iface(
        &self,
        name: &str,
        vni: u32,
        port: u16,
        dev: u32,
    ) -> Result<u32> {
        let mut links = self.handle.link().get().execute();
        while let Some(link) = links.try_next().await? {
            for attr in &link.attributes {
                if let rtnetlink::packet_route::link::LinkAttribute::IfName(ifname) = attr
                    && ifname == name
                {
                    return Ok(link.header.index);
                }
            }
        }
        let msg = LinkVxlan::new(name, vni)
            .dev(dev)
            .up()
            .port(port)
            .collect_metadata(true)
            .build();

        self.handle.link().add(msg).execute().await?;

        self.get_link_index_by_name(name).await
    }

    pub async fn get_iface_addrs(&self, iface: &str) -> Result<Vec<IpAddr>> {
        let link = self
            .handle
            .link()
            .get()
            .match_name(iface.to_string())
            .execute()
            .try_next()
            .await?
            .ok_or_else(|| Error::NotFound(format!("interface {iface}")))?;

        let mut addrs = self
            .handle
            .address()
            .get()
            .set_link_index_filter(link.header.index)
            .execute();

        let mut ips = Vec::new();
        while let Some(msg) = addrs.try_next().await? {
            for attr in msg.attributes {
                if let AddressAttribute::Address(ip) = attr {
                    ips.push(ip);
                }
            }
        }
        Ok(ips)
    }

    /// Create veth pair returning the ifindex for the primary and peer
    pub async fn create_veth_pair(&self, name: &str, peer_name: &str) -> Result<(u32, u32)> {
        self.handle
            .link()
            .add(LinkVeth::new(name, peer_name).up().build())
            .execute()
            .await?;

        let iface = self.get_link_index_by_name(name).await?;

        let peer = self.get_link_index_by_name(peer_name).await?;

        Ok((iface, peer))
    }

    pub async fn set_link_up(&self, index: u32) -> Result<()> {
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await?;
        Ok(())
    }

    pub async fn delete_link(&self, index: u32) -> Result<()> {
        self.handle.link().del(index).execute().await?;
        Ok(())
    }

    /// Renames an interface
    pub async fn rename_link(&self, index: u32, name: &str) -> Result<()> {
        self.handle
            .link()
            .set(
                LinkUnspec::new_with_index(index)
                    .name(name.to_string())
                    .build(),
            )
            .execute()
            .await?;
        Ok(())
    }

    /// Sets an IpAddr for a given ifindex
    pub async fn set_addr(&self, ifindex: u32, addr: IpAddr) -> Result<()> {
        if let Some(addr_msg) = self
            .handle
            .address()
            .get()
            .set_link_index_filter(ifindex)
            .execute()
            .try_next()
            .await?
            && addr_matches(&addr_msg, addr)
        {
            return Ok(());
        }
        self.handle
            .address()
            .add(ifindex, addr, 32)
            .execute()
            .await?;
        Ok(())
    }

    /// Adds linked scoped route for a given network
    pub async fn add_link_scope_route(
        &self,
        idx: u32,
        addr: IpAddr,
        prefix_length: u8,
    ) -> Result<()> {
        let route = match addr {
            IpAddr::V4(ipv4_addr) => RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(ipv4_addr, prefix_length)
                .output_interface(idx)
                .scope(RouteScope::Link)
                .build(),
            IpAddr::V6(ipv6_addr) => RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(ipv6_addr, prefix_length)
                .output_interface(idx)
                .scope(RouteScope::Link)
                .build(),
        };
        self.handle.route().add(route).execute().await?;
        Ok(())
    }

    /// Adds default route for given ifindex
    pub async fn add_default_route(&self, ifindex: u32, addr: IpAddr) -> Result<()> {
        let route = match addr {
            IpAddr::V4(ipv4_addr) => RouteMessageBuilder::<Ipv4Addr>::new()
                .output_interface(ifindex)
                .gateway(ipv4_addr)
                .build(),
            IpAddr::V6(ipv6_addr) => RouteMessageBuilder::<Ipv6Addr>::new()
                .output_interface(ifindex)
                .gateway(ipv6_addr)
                .build(),
        };
        self.handle.route().add(route).execute().await?;
        Ok(())
    }

    /// Adds a route to the main route table
    pub async fn add_host_route(&self, idx: u32, addr: IpAddr) -> Result<()> {
        let route = match addr {
            IpAddr::V4(ipv4_addr) => RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(ipv4_addr, 32)
                .output_interface(idx)
                .table_id(RouteHeader::RT_TABLE_MAIN.into())
                .scope(RouteScope::Link)
                .build(),
            IpAddr::V6(ipv6_addr) => RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(ipv6_addr, 128)
                .output_interface(idx)
                .table_id(RouteHeader::RT_TABLE_MAIN.into())
                .scope(RouteScope::Link)
                .build(),
        };
        self.handle.route().add(route).execute().await?;
        Ok(())
    }

    /// Sets a given ifindex to a specified network namespace
    pub async fn set_iface_to_netns(&self, index: u32, host_ns_fd: RawFd) -> Result<()> {
        self.handle
            .link()
            .set(
                LinkUnspec::new_with_index(index)
                    .setns_by_fd(host_ns_fd)
                    .build(),
            )
            .execute()
            .await?;
        Ok(())
    }

    pub async fn get_addrs_from_iface(&self, ifindex: u32) -> Result<Vec<IpAddr>> {
        let mut addrs = Vec::new();

        let mut iface_addrs = self
            .handle
            .address()
            .get()
            .set_link_index_filter(ifindex)
            .execute();

        while let Some(addr) = iface_addrs.try_next().await? {
            for attr in addr.attributes {
                if let AddressAttribute::Local(ip) = attr {
                    addrs.push(ip);
                }
            }
        }

        Ok(addrs)
    }
}

fn addr_matches(addr_message: &AddressMessage, addr: IpAddr) -> bool {
    addr_message.attributes.iter().any(|attr| match attr {
        AddressAttribute::Address(ip_addr) => *ip_addr == addr,
        _ => false,
    })
}
