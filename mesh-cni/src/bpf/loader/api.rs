use std::path::PathBuf;
use std::thread;
use std::thread::JoinHandle;

use aya::Ebpf;
use aya::programs::tc::{self};
use aya::programs::{SchedClassifier, TcAttachType};
use mesh_cni_api::bpf::v1::{AddContainerReply, AddContainerRequest};
use tonic::{Request, Response, Status};
use tracing::{error, info};

use crate::bpf::loader::LoaderState;
use crate::{Error, Result};

use mesh_cni_api::bpf::v1::bpf_server::Bpf as BpfApi;

const NET_NS_DIR: &str = "/var/run/mesh/netns";
const INGRESS_TC_NAME: &str = "mesh_cni_ingress";
const EGRESS_TC_NAME: &str = "mesh_cni_egress";

#[tonic::async_trait]
impl BpfApi for LoaderState {
    async fn add_container(
        &self,
        request: Request<AddContainerRequest>,
    ) -> Result<Response<AddContainerReply>, Status> {
        let request = request.into_inner();
        info!("received add request {:?}", request);
        let _iface = request.iface.clone();
        let _netns_name = request.net_namespace.clone();
        let ebpf = self.ebpf.clone();
        // entering a network namespace affects the entire thread so care shoudld be taken
        // doing this in an async context. For now just spawn a separate thread
        // to avoid any weird bugs related to network namespace entering/exiting
        let t: JoinHandle<Result<()>> = thread::spawn(move || {
            let iface = request.iface;
            let netns_name = request.net_namespace;
            let netns_name = PathBuf::from(netns_name);
            let netns_name = netns_name
                .file_name()
                .ok_or_else(|| Error::InvalidSandbox("failed to get netns name".into()))?;

            let net_ns_name = netns_name.to_str().ok_or_else(|| {
                Error::InvalidSandbox(format!("failed to get netns {}", netns_name.display()))
            })?;

            let path = format!("{}/{}", NET_NS_DIR, net_ns_name);
            info!("getting netns from {}", path);
            let netns = netns_rs::get_from_path(path)?;
            info!("entering network namespace {}", netns);

            let ebpf = ebpf.blocking_lock_owned();
            let mut ebpf = ebpf;
            netns.enter()?;
            let _ = tc::qdisc_add_clsact(&iface);
            info!(
                "adding tc progams to {} in network namespace {}",
                iface, netns
            );
            // call detach on delete?
            attach_tc_bpf_program(&mut ebpf, &iface, INGRESS_TC_NAME, TcAttachType::Ingress)?;
            attach_tc_bpf_program(&mut ebpf, &iface, EGRESS_TC_NAME, TcAttachType::Egress)?;

            Ok(())
        });
        match t.join() {
            Ok(r) => match r {
                Ok(_) => {}
                // TODO: probably could be _more_ correct here with the status code
                Err(e) => {
                    error!(%e, "failed attach bpf programs to interface");
                    return Err(Status::new(tonic::Code::Internal, e.to_string()));
                }
            },
            Err(_) => {
                return Err(Status::new(
                    tonic::Code::Internal,
                    "thread for bpf program attachment has panicked".to_string(),
                ));
            }
        };
        Ok(Response::new(AddContainerReply {
            interfaces: Vec::new(),
            ips: Vec::new(),
            routes: Vec::new(),
            dns: None,
        }))
    }
}

fn attach_tc_bpf_program(
    ebpf: &mut Ebpf,
    iface: &str,
    name: &str,
    attach_type: TcAttachType,
) -> Result<()> {
    let program: &mut SchedClassifier = ebpf
        .program_mut(name)
        .ok_or_else(|| Error::EbpfProgramError(format!("failed to load program {name}")))?
        .try_into()?;
    if let Err(e) = program.load()
        && !matches!(e, aya::programs::ProgramError::AlreadyLoaded)
    {
        return Err(e.into());
    };
    if let Err(e) = program.attach(iface, attach_type)
        && !matches!(e, aya::programs::ProgramError::AlreadyAttached)
    {
        return Err(e.into());
    }
    Ok(())
}
