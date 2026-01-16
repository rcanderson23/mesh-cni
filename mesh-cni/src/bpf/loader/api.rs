use mesh_cni_api::bpf::v1::{AddPodReply, AddPodRequest, bpf_server::Bpf as BpfApi};
use tonic::{Request, Response, Status};
use tracing::info;

use crate::{Result, bpf::loader::LoaderState};

const _NET_NS_DIR: &str = "/var/run/mesh/netns";

#[tonic::async_trait]
impl BpfApi for LoaderState {
    async fn add_pod(
        &self,
        request: Request<AddPodRequest>,
    ) -> Result<Response<AddPodReply>, Status> {
        let request = request.into_inner();
        info!("received add request {:?}", request);
        // let _ = tc::qdisc_add_clsact(&request.iface);
        // info!("adding tc ingress progam to {}", &request.iface);
        // let mut ingress_prog =
        //     SchedClassifier::from_pin(BPF_PROGRAM_INGRESS_TC.path()).map_err(|e| {
        //         error!(%e, "failed to load ingress program from pin");
        //         tonic::Status::new(Code::Internal, e.to_string())
        //     })?;
        //
        // if let Err(e) = ingress_prog.attach(&request.iface, TcAttachType::Ingress)
        //     && !matches!(e, aya::programs::ProgramError::AlreadyAttached)
        // {
        //     return Err(tonic::Status::new(Code::Internal, e.to_string()));
        // }
        Ok(Response::new(AddPodReply {
            interfaces: Vec::new(),
            ips: Vec::new(),
            routes: Vec::new(),
            dns: None,
        }))
    }
}
