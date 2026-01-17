use mesh_cni_api::bpf::v1::{DeletePodReply, DeletePodRequest, bpf_client::BpfClient};
use serde::Deserialize;
use tracing::{error, info};

use crate::{
    CNI_VERSION, Error,
    config::Args,
    response::{Response, Success},
    types::Input,
};

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
pub fn delete(args: &Args, input: Input) -> Response {
    info!("delete called, received input {:?}", input);
    let Some(prev) = input.previous_result else {
        return Error::NoPreviousResult("no previous result found".into())
            .into_response(CNI_VERSION);
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

    for interface in &prev.interfaces {
        if interface.sandbox.is_some() {
            continue;
        };

        let iface = interface.name.clone();
        let req = DeletePodRequest {
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

    Response::Success(Success {
        cni_version: prev.cni_version,
        interfaces: prev.interfaces,
        ips: prev.ips,
        routes: prev.routes,
        dns: prev.dns,
        custom: prev.custom,
    })
}

async fn request(req: DeletePodRequest) -> Result<DeletePodReply, Error> {
    let path = "unix:///var/run/mesh/mesh.sock";
    let mut client = BpfClient::connect(path).await?;
    let resp = client.delete_pod(req).await?;
    Ok(resp.into_inner())
}
