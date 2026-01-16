use std::collections::HashMap;

use mesh_cni_api::bpf::v1::{AddPodReply, AddPodRequest, bpf_client::BpfClient};
use serde::Deserialize;
use tracing::{error, info};

use crate::{
    CNI_VERSION, Error,
    config::Args,
    response::{Response, Success},
    types::Input,
};

pub fn add(args: &Args, input: Input) -> Response {
    info!(
        "add called, received input {:?} for containerid {}",
        input, &args.container_id
    );
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

    for interface in &prev.interfaces {
        if interface.sandbox.is_some() {
            continue;
        };

        let iface = interface.name.clone();
        let req = AddPodRequest {
            iface,
            net_namespace: None,
            container_id: args.container_id.clone(),
            chained: true,
        };
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
    let mut client = BpfClient::connect(path).await?;
    let resp = client.add_pod(req).await?;
    Ok(resp.into_inner())
}
