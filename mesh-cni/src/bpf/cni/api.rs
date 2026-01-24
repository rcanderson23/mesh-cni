use std::path::{Path, PathBuf};

use aya::programs::{
    SchedClassifier, TcAttachType,
    links::{FdLink, LinkError, PinnedLink},
    tc,
};
use mesh_cni_api::bpf::v1::{
    AddPodReply, AddPodRequest, DeletePodReply, DeletePodRequest, bpf_server::Bpf as BpfApi,
};
use tonic::{Code, Request, Response, Status};
use tracing::{error, info};

use crate::{
    Result,
    bpf::{BPF_MESH_LINKS_DIR, BPF_PROGRAM_INGRESS_TC},
};

const _NET_NS_DIR: &str = "/var/run/mesh/netns";
const MESH_INGRESS_LINK_PREFIX: &str = "mesh_cni_ingress_";

pub struct LoaderState;

// TODO: this only handles chained creation correctly
//
// Spec says there SHOULD be a DEL call in between ADD calls so we need
// to try to clean up on failed attach and pin calls
#[tonic::async_trait]
impl BpfApi for LoaderState {
    async fn add_pod(
        &self,
        request: Request<AddPodRequest>,
    ) -> std::result::Result<Response<AddPodReply>, Status> {
        let request = request.into_inner();
        info!("received add request {:?}", request);
        let _ = tc::qdisc_add_clsact(&request.iface);
        info!("adding tc ingress progam to {}", &request.iface);
        attach_and_pin_links(
            &request.iface,
            BPF_PROGRAM_INGRESS_TC.path(),
            TcAttachType::Ingress,
        )
        .map_err(|e| tonic::Status::new(Code::Internal, e.to_string()))?;

        info!("adding tc egress progam to {}", &request.iface);
        if let Err(e) = attach_and_pin_links(
            &request.iface,
            BPF_PROGRAM_INGRESS_TC.path(),
            TcAttachType::Egress,
        ) {
            let ingress_path = pin_path(&request.iface, TcAttachType::Ingress);
            let egress_path = pin_path(&request.iface, TcAttachType::Egress);
            for path in [ingress_path, egress_path] {
                let Err(u) = unpin_path(path) else {
                    continue;
                };
                error!(%u, "failed to unpin path");
            }

            error!(%e, "failed to attach and pin egress link");
            Err(tonic::Status::new(Code::Internal, e.to_string()))
        } else {
            Ok(Response::new(AddPodReply {
                interfaces: Vec::new(),
                ips: Vec::new(),
                routes: Vec::new(),
                dns: None,
            }))
        }
    }

    async fn delete_pod(
        &self,
        request: Request<DeletePodRequest>,
    ) -> std::result::Result<Response<DeletePodReply>, Status> {
        let request = request.into_inner();
        info!("received delete request {:?}", request);

        let ingress_path = pin_path(&request.iface, TcAttachType::Ingress);
        let egress_path = pin_path(&request.iface, TcAttachType::Egress);

        for path in [ingress_path, egress_path] {
            unpin_path(path).map_err(|e| tonic::Status::new(Code::Internal, e.to_string()))?;
        }

        Ok(Response::new(DeletePodReply {}))
    }
}

fn unpin_path(path: impl AsRef<Path>) -> Result<()> {
    match path.as_ref().try_exists() {
        Ok(true) => {}
        Ok(false) => return Ok(()),
        Err(e) => {
            return Err(e.into());
        }
    }
    match PinnedLink::from_pin(path) {
        Ok(link) => {
            let _link = link.unpin()?;
        }
        Err(LinkError::SyscallError(err))
            if err.io_error.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn pin_path(iface: &str, attach_type: TcAttachType) -> PathBuf {
    match attach_type {
        TcAttachType::Ingress => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{}_ingress", MESH_INGRESS_LINK_PREFIX, iface)),
        TcAttachType::Egress => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{}_egress", MESH_INGRESS_LINK_PREFIX, iface)),
        TcAttachType::Custom(_) => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{}_custom", MESH_INGRESS_LINK_PREFIX, iface)),
    }
}

fn attach_and_pin_links(
    iface: &str,
    path: impl AsRef<Path>,
    attach_type: TcAttachType,
) -> Result<()> {
    let mut prog = SchedClassifier::from_pin(path)?;

    let link_id = prog.attach(iface, attach_type)?;

    let link = prog.take_link(link_id)?;
    let link: FdLink = link.try_into()?;
    let pin_path = match attach_type {
        TcAttachType::Ingress => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{}_ingress", MESH_INGRESS_LINK_PREFIX, iface)),
        TcAttachType::Egress => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{}_egress", MESH_INGRESS_LINK_PREFIX, iface)),
        TcAttachType::Custom(_) => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{}_custom", MESH_INGRESS_LINK_PREFIX, iface)),
    };
    link.pin(pin_path)?;
    Ok(())
}
