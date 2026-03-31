use anyhow::bail;
use regex::Regex;
use rtnetlink::{Handle, packet_route::link::LinkAttribute};
use tokio_stream::StreamExt;

use crate::Result;

pub(crate) async fn link_index_by_name(handle: &Handle, name: &str) -> Result<u32> {
    let link = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute()
        .try_next()
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing interface {name}"))?;

    Ok(link.header.index)
}

pub(crate) async fn find_first_iface_match(handle: &Handle, iface_regex: &str) -> Result<String> {
    let iface_regex = Regex::new(iface_regex)?;
    let mut links = handle.link().get().execute();
    while let Some(link) = links.try_next().await? {
        for attr in &link.attributes {
            if let rtnetlink::packet_route::link::LinkAttribute::IfName(name) = attr
                && iface_regex.is_match(name)
            {
                return Ok(name.clone());
            }
        }
    }
    bail!("failed to find interface matching regex {iface_regex}")
}

pub(crate) async fn get_mtu_from_iface(handle: &Handle, iface: &str) -> Result<u32> {
    let link = handle
        .link()
        .get()
        .match_name(iface.to_string())
        .execute()
        .try_next()
        .await?
        .ok_or_else(|| anyhow::anyhow!("interface not found: {iface}"))?;

    for attr in link.attributes {
        if let LinkAttribute::Mtu(mtu) = attr {
            return Ok(mtu);
        }
    }
    bail!("failed to find MTU on {iface}")
}
