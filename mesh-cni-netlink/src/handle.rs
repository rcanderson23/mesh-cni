use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZero;

use ipnetwork::IpNetwork;
use regex::Regex;
use rtnetlink::packet_route::route::RouteMetric;
use rtnetlink::{Handle, packet_route::link::LinkAttribute};
use rtnetlink::{LinkDummy, LinkVxlan, RouteMessageBuilder};
use tokio_stream::StreamExt;

use crate::{Error, Result};

pub struct Netlink {
    handle: Handle,
}

impl Netlink {
    pub fn try_new() -> Result<Self> {
        let (conn, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(conn);
        Ok(Self { handle })
    }

    pub async fn link_index_by_name(&self, iface: &str) -> Result<u32> {
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

        self.link_index_by_name(iface).await
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

        self.link_index_by_name(name).await
    }
}
