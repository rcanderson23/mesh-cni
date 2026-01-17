use aya::programs::{SchedClassifier, TcAttachType, links::FdLink, tc};
use mesh_cni_api::bpf::v1::{AddPodReply, AddPodRequest, bpf_server::Bpf as BpfApi};
use tonic::{Code, Request, Response, Status};
use tracing::{error, info};

use crate::{
    Result,
    bpf::{BPF_MESH_LINKS_DIR, BPF_PROGRAM_INGRESS_TC, loader::LoaderState},
};

const _NET_NS_DIR: &str = "/var/run/mesh/netns";

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
            .map_err(|e| tonic::Status::new(Code::Internal, "failed to convert link"))?;
        let path = format!("{}/mesh_cni_ingress_{}", BPF_MESH_LINKS_DIR, request.iface);
        link.pin(path)
            .map_err(|e| tonic::Status::new(Code::Internal, e.to_string()))?;

        Ok(Response::new(AddPodReply {
            interfaces: Vec::new(),
            ips: Vec::new(),
            routes: Vec::new(),
            dns: None,
        }))
    }
}
