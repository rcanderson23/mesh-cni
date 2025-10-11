use aya::programs::tc::{self};
use aya::programs::{SchedClassifier, TcAttachType};
use mesh_cni_api::bpf::v1::{AddPodReply, AddPodRequest};
use tonic::{Code, Request, Response, Status};
use tracing::{error, info};

use crate::Result;
use crate::bpf::loader::LoaderState;
use crate::bpf::loader::state::BPF_PROGRAM_INGRESS_PATH;

use mesh_cni_api::bpf::v1::bpf_server::Bpf as BpfApi;

const _NET_NS_DIR: &str = "/var/run/mesh/netns";

#[tonic::async_trait]
impl BpfApi for LoaderState {
    async fn add_pod(
        &self,
        request: Request<AddPodRequest>,
    ) -> Result<Response<AddPodReply>, Status> {
        // TODO: state can probably be removed entirely by pinning program and
        // loading from bpffs on request which would allow for a single load call
        let request = request.into_inner();
        info!("received add request {:?}", request);
        let _ = tc::qdisc_add_clsact(&request.iface);
        info!("adding tc ingress progam to {}", &request.iface);
        let mut ingress_prog =
            SchedClassifier::from_pin(BPF_PROGRAM_INGRESS_PATH).map_err(|e| {
                error!(%e, "failed to load ingress program from pin");
                tonic::Status::new(Code::Internal, e.to_string())
            })?;

        if let Err(e) = ingress_prog.attach(&request.iface, TcAttachType::Ingress)
            && !matches!(e, aya::programs::ProgramError::AlreadyAttached)
        {
            return Err(tonic::Status::new(Code::Internal, e.to_string()));
        }
        Ok(Response::new(AddPodReply {
            interfaces: Vec::new(),
            ips: Vec::new(),
            routes: Vec::new(),
            dns: None,
        }))
    }
}
