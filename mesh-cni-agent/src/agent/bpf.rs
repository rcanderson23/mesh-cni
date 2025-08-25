use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::{fs, thread};

use aya::Ebpf;
use aya::maps::Map;
use aya::programs::tc::{self, SchedClassifierLinkId};
use aya::programs::{SchedClassifier, TcAttachType};
use mesh_cni_api::bpf::v1::{AddContainerReply, AddContainerRequest};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, warn};

use crate::http::shutdown;
use crate::{Error, Result};

use mesh_cni_api::bpf::v1::bpf_server::{Bpf as BpfApi, BpfServer};

const NET_NS_DIR: &str = "/var/run/mesh/netns";
const BPF_FS_DIR: &str = "/sys/fs/bpf";
const INGRESS_TC_NAME: &str = "mesh_cni_ingress";
const EGRESS_TC_NAME: &str = "mesh_cni_egress";

#[derive(Clone)]
pub(crate) struct State {
    ebpf: Arc<Mutex<Ebpf>>,
    // TODO: consider remvoing as these are likely unneeded
    ifaces: Arc<Mutex<BTreeMap<(String, String), (SchedClassifierLinkId, SchedClassifierLinkId)>>>,
}

impl State {
    pub fn try_new() -> Result<State> {
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/mesh-cni"
        )))?;
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            warn!(%e, "failed to init ebpf logger");
        }
        let mut ifaces = BTreeMap::default();
        // info!("adding root netns eth0 tc");
        // let iface = "eth0";
        // let _ = tc::qdisc_add_clsact(iface);
        // let ingress_id =
        //     attach_tc_bpf_program(&mut ebpf, iface, INGRESS_TC_NAME, TcAttachType::Ingress)?;
        // let egress_id =
        //     attach_tc_bpf_program(&mut ebpf,
        //
        // ifaces.insert((iface.into(), "root".into()), (ingress_id, egress_id));

        // TODO: pin programs to survive restart
        //
        // let ingress = ebpf
        //     .map_mut("mesh_cni_ingress")
        //     .ok_or_else(|| Error::EbpfProgramError("failed to load ingress program".into()))?;
        // ingress.pin(format!("{}/{}", BPF_FS_DIR, INGRESS_TC_NAME))?;
        // let egress = ebpf
        //     .map_mut("mesh_cni_egress")
        //     .ok_or_else(|| Error::EbpfProgramError("failed to load ingress program".into()))?;
        // egress.pin(format!("{}/{}", BPF_FS_DIR, INGRESS_TC_NAME))?;
        Ok(Self {
            ebpf: Arc::new(Mutex::new(ebpf)),
            ifaces: Arc::new(Mutex::new(ifaces)),
        })
    }
    pub async fn take_map(&self, name: &str) -> Option<Map> {
        let ebpf = self.ebpf.lock().await;
        let mut ebpf = ebpf;
        ebpf.take_map(name)
    }
}

#[tonic::async_trait]
impl BpfApi for State {
    async fn add_container(
        &self,
        request: Request<AddContainerRequest>,
    ) -> Result<Response<AddContainerReply>, Status> {
        let request = request.into_inner();
        info!("received add request {:?}", request);
        let iface = request.iface.clone();
        let netns_name = request.net_namespace.clone();
        let ebpf = self.ebpf.clone();
        // entering a network namespace affects the entire thread so care shoudld be taken
        // doing this in an async context. For now just spawn a separate thread
        // to avoid any weird bugs related to network namespace entering/exiting
        let t: JoinHandle<Result<(SchedClassifierLinkId, SchedClassifierLinkId)>> =
            thread::spawn(move || {
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
                let ingress_id = attach_tc_bpf_program(
                    &mut ebpf,
                    &iface,
                    INGRESS_TC_NAME,
                    TcAttachType::Ingress,
                )?;
                let egress_id =
                    attach_tc_bpf_program(&mut ebpf, &iface, EGRESS_TC_NAME, TcAttachType::Egress)?;

                Ok((ingress_id, egress_id))
            });
        match t.join() {
            Ok(r) => match r {
                Ok(ids) => {
                    let ifaces = self.ifaces.lock().await;
                    let mut ifaces = ifaces;
                    ifaces.insert((iface, netns_name), ids)
                }
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
        Ok(Response::new(AddContainerReply {}))
    }
}

fn attach_tc_bpf_program(
    ebpf: &mut Ebpf,
    iface: &str,
    name: &str,
    attach_type: TcAttachType,
) -> Result<SchedClassifierLinkId> {
    let program: &mut SchedClassifier = ebpf
        .program_mut(name)
        .ok_or_else(|| Error::EbpfProgramError(format!("failed to load program {name}")))?
        .try_into()?;
    if let Err(e) = program.load()
        && !matches!(e, aya::programs::ProgramError::AlreadyLoaded)
    {
        return Err(e.into());
    };
    Ok(program.attach(iface, attach_type)?)
}
