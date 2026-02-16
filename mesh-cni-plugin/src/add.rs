use std::collections::{HashMap, HashSet};

use mesh_cni_api::cni::v1::{AddPodReply, AddPodRequest, cni_client::CniClient};
use serde::Deserialize;
use tracing::{error, info};

use crate::{
    CNI_VERSION, Error,
    config::Args,
    response::{Response, Success},
    types::Input,
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
pub fn add(args: &Args, input: Input) -> Response {
    info!(
        "add called, received input {:?} for containerid {}",
        input, &args.container_id
    );
    let Some(pod_name) = args.args.get("K8S_POD_NAME") else {
        return Error::Parse("missing pod name".to_string()).into_response(CNI_VERSION);
    };
    let pod_name = pod_name.to_string();
    let Some(pod_namespace) = args.args.get("K8S_POD_NAMESPACE") else {
        return Error::Parse("missing pod namespace".to_string()).into_response(CNI_VERSION);
    };
    let pod_namespace = pod_namespace.to_string();

    // Unchained
    let Some(prev) = input.previous_result else {
        let Ok(net_namespace) = args.net_ns.clone().unwrap().into_os_string().into_string() else {
            return Error::InvalidRequiredEnvVariables(
                "failed to convert network namespace to string".into(),
            )
            .into_response(CNI_VERSION);
        };
        let req = AddPodRequest {
            iface: args.ifname.clone(),
            net_namespace: Some(net_namespace),
            container_id: args.container_id.clone(),
            chained: false,
            pod_name,
            pod_namespace,
        };
        let resp = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(request(req));
        let r = match resp {
            Ok(r) => {
                info!("received reply {:?}", &r);
                r
            }
            Err(e) => {
                error!(%e, "failed request to mesh socket");
                return Error::Ebpf(e.to_string()).into_response(CNI_VERSION);
            }
        };

        let interfaces = r.interfaces.iter().map(|i| i.to_owned()).collect();
        let success = Success {
            cni_version: CNI_VERSION,
            interfaces,
            ips: r.ips,
            routes: r.routes,
            dns: r.dns,
            custom: HashMap::new(),
        };
        info!("add response {:?}", success);
        return Response::Success(success);
    };

    // Chained
    let prev = match Success::deserialize(prev) {
        Ok(prev) => prev,
        Err(e) => {
            error!(%e, "failed to deserialize previous results");
            return Error::from(e).into_response(CNI_VERSION);
        }
    };

    if prev.interfaces.is_empty() {
        error!("previous response is missing interfaces");
        return Error::MissingInterfaces.into_response(CNI_VERSION);
    }

    let mut reqs = Vec::new();
    let mut seen_iface = HashSet::new();

    for interface in &prev.interfaces {
        let Some(netns) = &interface.sandbox else {
            continue;
        };
        let netns = netns.clone();

        let iface_key = format!("{netns}:{}", interface.name);
        if seen_iface.insert(iface_key) {
            reqs.push(AddPodRequest {
                iface: interface.name.clone(),
                net_namespace: Some(netns.clone()),
                container_id: args.container_id.clone(),
                chained: true,
                pod_name: pod_name.clone(),
                pod_namespace: pod_namespace.clone(),
            });
        }
    }

    if reqs.is_empty() {
        return Error::Parse(
            "previous response is missing pod netns interface entries".to_string(),
        )
        .into_response(CNI_VERSION);
    }

    for req in reqs {
        let resp = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(request(req));
        match resp {
            Ok(r) => {
                info!("received reply {:?}", &r);
            }
            Err(e) => {
                error!(%e, "failed request to mesh socket");
                return Error::Ebpf(e.to_string()).into_response(CNI_VERSION);
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
    Response::Success(success)
}

async fn request(req: AddPodRequest) -> Result<AddPodReply, Error> {
    let path = "unix:///var/run/mesh/mesh.sock";
    let mut client = CniClient::connect(path).await?;
    let resp = client.add_pod(req).await?;
    Ok(resp.into_inner())
}
