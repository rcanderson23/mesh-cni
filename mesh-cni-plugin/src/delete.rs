use std::{collections::HashMap, net::IpAddr};

use mesh_cni_api::cni::v1::DeletePodRequest;
use mesh_cni_netlink::Netlink;
use serde::Deserialize;
use tracing::{error, info};

use crate::{
    CNI_VERSION, Error,
    add::host_veth_name,
    client::new_cni_client,
    config::Args,
    ebpf::unpin_iface_paths,
    netns::NetnsRestore,
    response::{Response, Success},
    types::Input,
};

// https://www.cni.dev/docs/spec/#del-remove-container-from-network-or-un-apply-modifications
//Input:
//
//The runtime will provide a JSON-serialized plugin configuration object (defined below) on standard in.
//
//Required environment parameters:
//
//    CNI_COMMAND
//    CNI_CONTAINERID
//    CNI_IFNAME
//
//Optional environment parameters:
//
//    CNI_NETNS
//    CNI_ARGS
//    CNI_PATH
//
pub async fn delete(args: &Args, input: Input) -> Response {
    match _delete(args, input).await {
        Ok(r) => r,
        Err(e) => e.into_response(CNI_VERSION),
    }
}
async fn _delete(args: &Args, input: Input) -> Result<Response, Error> {
    info!("delete called, received input {:?}", input);
    let _host_netns_guard = NetnsRestore::current_thread()?;

    // Unchained
    if let Some(prev) = input.previous_result {
        let prev = Success::deserialize(prev)?;
        if prev.interfaces.is_empty() {
            error!("previous response is missing interfaces");
            return Err(Error::MissingInterfaces);
        }
        let mut ipv4_addrs = Vec::new();
        for ip in &prev.ips {
            if let IpAddr::V4(ipv4) = ip.address.ip() {
                ipv4_addrs.push(ipv4.octets().to_vec());
            }
        }

        if ipv4_addrs.is_empty() {
            for interface in &prev.interfaces {
                let Some(netns) = &interface.sandbox else {
                    continue;
                };
                if !netns.exists() {
                    continue;
                }

                let pod_ns = netns_rs::get_from_path(netns)?;
                pod_ns.enter()?;
                let nl = Netlink::try_new()?;

                for addr in nl.get_iface_addrs(&interface.name).await? {
                    if let IpAddr::V4(ipv4) = addr {
                        ipv4_addrs.push(ipv4.octets().to_vec());
                    }
                }
            }
        }

        if !ipv4_addrs.is_empty() {
            let mut client = new_cni_client().await?;
            client
                .delete_pod(DeletePodRequest { ipv4: ipv4_addrs })
                .await?;
        }

        for interface in &prev.interfaces {
            unpin_iface_paths(&args.container_id, &interface.name)?;
        }
        unpin_iface_paths(&args.container_id, "lo")?;
        unpin_iface_paths(&args.container_id, &host_veth_name(&args.container_id))?;
        return Ok(Response::Success(Success {
            cni_version: prev.cni_version,
            interfaces: prev.interfaces,
            ips: prev.ips,
            routes: prev.routes,
            dns: prev.dns,
            custom: prev.custom,
        }));
    }

    // Chained
    unpin_iface_paths(&args.container_id, &args.ifname)?;
    unpin_iface_paths(&args.container_id, "lo")?;
    unpin_iface_paths(&args.container_id, &host_veth_name(&args.container_id))?;

    let Some(netns) = &args.net_ns else {
        return Ok(Response::Success(Success {
            cni_version: CNI_VERSION,
            interfaces: Vec::default(),
            ips: Vec::default(),
            routes: Vec::default(),
            dns: None,
            custom: HashMap::default(),
        }));
    };
    if !netns.exists() {
        return Ok(Response::Success(Success {
            cni_version: CNI_VERSION,
            interfaces: Vec::default(),
            ips: Vec::default(),
            routes: Vec::default(),
            dns: None,
            custom: HashMap::default(),
        }));
    }

    let pod_ns = netns_rs::get_from_path(netns)?;
    pod_ns.enter()?;
    let nl = Netlink::try_new()?;

    let mut ipv4_addrs = Vec::new();
    for addr in nl.get_iface_addrs(&args.ifname).await? {
        if let IpAddr::V4(ipv4) = addr {
            ipv4_addrs.push(ipv4.octets().to_vec());
        }
    }
    let mut client = new_cni_client().await?;
    client
        .delete_pod(DeletePodRequest { ipv4: ipv4_addrs })
        .await?;

    Ok(Response::Success(Success {
        cni_version: CNI_VERSION,
        interfaces: Vec::default(),
        ips: Vec::default(),
        routes: Vec::default(),
        dns: None,
        custom: HashMap::default(),
    }))
}
