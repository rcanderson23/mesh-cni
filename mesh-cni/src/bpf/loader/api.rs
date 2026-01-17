use std::path::PathBuf;

use aya::{
    pin::PinError,
    programs::{
        SchedClassifier, TcAttachType,
        links::{FdLink, LinkError, PinnedLink},
        tc,
    },
};
use mesh_cni_api::bpf::v1::{
    AddPodReply, AddPodRequest, DeletePodReply, DeletePodRequest, bpf_server::Bpf as BpfApi,
};
use tonic::{Code, Request, Response, Status};
use tracing::{error, info};

use crate::{
    Result,
    bpf::{BPF_MESH_LINKS_DIR, BPF_PROGRAM_INGRESS_TC, loader::LoaderState},
};

const _NET_NS_DIR: &str = "/var/run/mesh/netns";
const MESH_INGRESS_LINK_PREFIX: &str = "mesh_cni_ingress_";

fn ingress_link_path(iface: &str) -> PathBuf {
    PathBuf::from(BPF_MESH_LINKS_DIR).join(format!("{}{}", MESH_INGRESS_LINK_PREFIX, iface))
}

#[tonic::async_trait]
impl BpfApi for LoaderState {
    async fn add_pod(
        &self,
        request: Request<AddPodRequest>,
    ) -> Result<Response<AddPodReply>, Status> {
        let request = request.into_inner();
        info!("received add request {:?}", request);
        let _ = tc::qdisc_add_clsact(&request.iface);
        info!("adding tc ingress progam to {}", &request.iface);
        let mut ingress_prog =
            SchedClassifier::from_pin(BPF_PROGRAM_INGRESS_TC.path()).map_err(|e| {
                error!(%e, "failed to load ingress program from pin");
                tonic::Status::new(Code::Internal, e.to_string())
            })?;

        let link_id = ingress_prog
            .attach(&request.iface, TcAttachType::Ingress)
            .map_err(|e| {
                error!(%e, "failed to attach ingress program");
                tonic::Status::new(Code::Internal, e.to_string())
            })?;

        let link = ingress_prog
            .take_link(link_id)
            .map_err(|e| tonic::Status::new(Code::Internal, e.to_string()))?;
        let link: FdLink = link
            .try_into()
            .map_err(|e: LinkError| tonic::Status::new(Code::Internal, e.to_string()))?;
        let path = ingress_link_path(&request.iface);
        link.pin(path)
            .map_err(|e: PinError| tonic::Status::new(Code::Internal, e.to_string()))?;

        Ok(Response::new(AddPodReply {
            interfaces: Vec::new(),
            ips: Vec::new(),
            routes: Vec::new(),
            dns: None,
        }))
    }

    async fn delete_pod(
        &self,
        request: Request<DeletePodRequest>,
    ) -> Result<Response<DeletePodReply>, Status> {
        let request = request.into_inner();
        info!("received delete request {:?}", request);

        let path = ingress_link_path(&request.iface);
        match PinnedLink::from_pin(&path) {
            Ok(link) => {
                let _link = link
                    .unpin()
                    .map_err(|e| tonic::Status::new(Code::Internal, e.to_string()))?;
            }
            Err(LinkError::SyscallError(err))
                if err.io_error.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(tonic::Status::new(Code::Internal, e.to_string())),
        }

        Ok(Response::new(DeletePodReply {}))
    }
}
