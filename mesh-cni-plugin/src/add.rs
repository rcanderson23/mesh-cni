use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsRawFd,
    path::PathBuf,
};

use aya::programs::TcAttachType;
use ipnetwork::IpNetwork;
use mesh_cni_api::cni::v1::{AddChainedRequest, AddVxlanRequest, DeletePodRequest};
use mesh_cni_ebpf_meta::BPF_PROGRAM_VXLAN_VETH_EGRESS_TC;
use mesh_cni_netlink::Netlink;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{error, info};

use crate::{
    CNI_VERSION, Error,
    client::new_cni_client,
    config::Args,
    ebpf::{attach_and_pin_links, attach_pod_bpf, unpin_iface_paths},
    netns::NetnsRestore,
    response::{Response, Success},
    types::{Input, Interface, Ip},
};

// https://www.cni.dev/docs/spec/#add-add-container-to-network-or-apply-modifications
// Input:
//
//The runtime will provide a JSON-serialized plugin configuration object (defined below) on standard in.
//
//Required environment parameters:
//
//    CNI_COMMAND
//    CNI_CONTAINERID
//    CNI_NETNS
//    CNI_IFNAME
//
//Optional environment parameters:
//
//    CNI_ARGS
//    CNI_PATH
//
pub async fn add(args: &Args, input: Input) -> Response {
    match _add(args, input).await {
        Ok(r) => r,
        Err(e) => {
            error!(%e, "failed to setup pod networking");
            e.into_response(CNI_VERSION)
        }
    }
}
async fn _add(args: &Args, input: Input) -> Result<Response, Error> {
    info!(
        "add called, received input {:?} for containerid {}",
        input, &args.container_id
    );
    info!("{:?}", &args.args);
    let Some(pod_name) = args.args.get("K8S_POD_NAME") else {
        return Err(Error::Parse("missing pod name".to_string()));
    };
    let pod_name = pod_name.to_string();
    let Some(pod_namespace) = args.args.get("K8S_POD_NAMESPACE") else {
        return Err(Error::Parse("missing pod namespace".to_string()));
    };
    let pod_namespace = pod_namespace.to_string();

    // Unchained
    let Some(prev) = input.previous_result else {
        let Some(net_ns) = args.net_ns.clone() else {
            return Err(Error::InvalidRequiredEnvVariables(
                "failed to convert network namespace to string".into(),
            ));
        };
        let success = add_vxlan(
            pod_name,
            pod_namespace,
            &args.ifname,
            &args.container_id,
            net_ns,
        )
        .await?;
        info!("add response {:?}", success);
        return Ok(Response::Success(success));
    };

    // Chained
    let prev = match Success::deserialize(prev) {
        Ok(prev) => prev,
        Err(e) => {
            error!(%e, "failed to deserialize previous results");
            return Err(Error::from(e));
        }
    };

    if prev.interfaces.is_empty() {
        error!("previous response is missing interfaces");
        return Err(Error::MissingInterfaces);
    }

    let mut reqs = Vec::new();
    let mut seen_iface = HashSet::new();

    for interface in &prev.interfaces {
        let Some(netns) = interface.sandbox.clone() else {
            continue;
        };
        let iface_key = format!("{}:{}", netns.display(), interface.name);
        if seen_iface.insert(iface_key) {
            add_chained(&interface.name, &args.container_id, &netns).await?;
            reqs.push(AddChainedRequest {
                pod_name: pod_name.clone(),
                pod_namespace: pod_namespace.clone(),
            });
        }
    }

    if reqs.is_empty() {
        return Err(Error::Parse(
            "previous response is missing pod netns interface entries".to_string(),
        ));
    }

    let mut client = new_cni_client().await?;
    for req in reqs {
        match client.add_chained_pod(req).await {
            Ok(r) => {
                info!("received reply {:?}", &r);
            }
            Err(e) => {
                error!(%e, "failed request to mesh socket");
                return Err(Error::Tonic(e));
            }
        }
    }

    let success = Success {
        cni_version: prev.cni_version,
        interfaces: prev.interfaces,
        ips: prev.ips,
        routes: prev.routes,
        dns: prev.dns,
        custom: prev.custom,
    };
    info!("add response {:?}", success);
    Ok(Response::Success(success))
}

async fn add_vxlan(
    pod_name: String,
    pod_namespace: String,
    iface: &str,
    container_id: &str,
    netns: PathBuf,
) -> Result<Success, Error> {
    let pod_ns = netns_rs::get_from_path(&netns)?;
    let pod_fd = pod_ns.file().as_raw_fd();
    let host_netns_guard = NetnsRestore::current_thread()?;

    let host_veth_name = host_veth_name(container_id);
    let tmp_iface_name = tmp_iface_name(container_id);

    let nl = Netlink::try_new()?;
    let (pod_ifindex, host_ifindex) = nl
        .create_veth_pair(&tmp_iface_name, &host_veth_name)
        .await?;
    attach_and_pin_links(
        &host_veth_name,
        container_id,
        BPF_PROGRAM_VXLAN_VETH_EGRESS_TC.path(),
        TcAttachType::Ingress, // need to be ingress attach coming from the pod netns
    )?;

    let mut client = match new_cni_client().await {
        Ok(c) => c,
        Err(e) => {
            let _ = unpin_iface_paths(container_id, &host_veth_name);
            let _ = nl.delete_link(host_ifindex).await;
            return Err(e);
        }
    };
    let resp = match client
        .add_vxlan_pod(AddVxlanRequest {
            pod_name,
            pod_namespace,
            chained: false,
            host_ifindex,
        })
        .await
    {
        Ok(resp) => resp.into_inner(),
        Err(e) => {
            if let Err(unpin_err) = unpin_iface_paths(container_id, &host_veth_name) {
                error!(%unpin_err, host_veth_name, "failed to unpin host tc links during vxlan add rollback");
            }
            if let Err(delete_err) = nl.delete_link(pod_ifindex).await {
                error!(%delete_err, pod_ifindex, "failed to delete veth pair during vxlan add rollback");
            }
            return Err(e.into());
        }
    };

    let pod_addr = bytes_to_addr(&resp.ipv4)?;
    let host_addr = bytes_to_addr(&resp.ipv4_gateway)?;
    let prefix_length = match pod_addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if let Err(e) = async {
        nl.set_addr(host_ifindex, host_addr).await?;
        nl.set_link_up(host_ifindex).await?;
        nl.add_host_route(host_ifindex, pod_addr).await?;
        nl.set_iface_to_netns(pod_ifindex, pod_fd).await?;

        // Pod setup
        pod_ns.enter()?;

        let nl = Netlink::try_new()?;
        let pod_ifindex = nl.get_link_index_by_name(&tmp_iface_name).await?;
        nl.rename_link(pod_ifindex, iface).await?;
        attach_pod_bpf(iface, container_id)?;
        nl.set_link_up(pod_ifindex).await?;

        nl.set_addr(pod_ifindex, pod_addr).await?;

        nl.add_link_scope_route(pod_ifindex, host_addr, prefix_length)
            .await?;

        nl.add_default_route(pod_ifindex, host_addr).await?;

        Ok::<(), Error>(())
    }
    .await
    {
        // Best effort delete to avoid leaking IPs as some information won't be captured by the delete call following the failure
        drop(host_netns_guard);

        let _ = client
            .delete_pod(DeletePodRequest {
                ipv4: vec![resp.ipv4],
            })
            .await;
        let _ = unpin_iface_paths(container_id, &host_veth_name);
        let _ = unpin_iface_paths(container_id, iface);
        let _ = unpin_iface_paths(container_id, "lo");
        let _ = nl.delete_link(host_ifindex).await;
        return Err(e);
    }
    // TODO: support ipv6

    Ok(Success {
        interfaces: vec![
            Interface {
                name: iface.to_string(),
                sandbox: Some(netns),
                ..Default::default()
            },
            Interface {
                name: host_veth_name.clone(),
                sandbox: None,
                ..Default::default()
            },
        ],
        ips: vec![Ip {
            address: IpNetwork::new(pod_addr, prefix_length)?,
            gateway: Some(host_addr),
            interface: Some(0),
        }],
        cni_version: CNI_VERSION,
        routes: Vec::default(),
        dns: None,
        custom: HashMap::default(),
    })
}

async fn add_chained(iface: &str, container_id: &str, netns: &PathBuf) -> Result<(), Error> {
    let pod_ns = netns_rs::get_from_path(netns)?;
    let _host_netns_guard = NetnsRestore::current_thread()?;
    pod_ns.enter()?;

    attach_pod_bpf(iface, container_id)?;
    Ok(())
}

// linux iface names are resetricted to 16 characters
pub(crate) fn host_veth_name(container_id: &str) -> String {
    let digest = Sha256::digest(container_id.as_bytes());
    let hex = format!("{:x}", digest);

    format!("mesh{}", &hex[..11])
}

// linux iface names are resetricted to 16 characters
fn tmp_iface_name(container_id: &str) -> String {
    let digest = Sha256::digest(container_id.as_bytes());
    let hex = format!("{:x}", digest);

    format!("tmp{}", &hex[..12])
}

fn bytes_to_addr(bytes: &[u8]) -> Result<IpAddr, Error> {
    match bytes.len() {
        4 => {
            let octets: [u8; 4] = bytes.try_into().unwrap();
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        16 => {
            let octets: [u8; 16] = bytes.try_into().unwrap();
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err(Error::Conversion(format!(
            "bytes length was not 4 or 16, got {}",
            bytes.len()
        ))),
    }
}
