use std::fs::{self, File};
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::Arc;

use aya::Ebpf;
use aya::maps::Map;
use aya::programs::cgroup_sock_addr::CgroupSockAddrLinkId;
use aya::programs::{CgroupAttachMode, CgroupSockAddr, SchedClassifier};
use std::sync::Mutex;
use tracing::{error, info, warn};

use crate::bpf::loader::INGRESS_TC_NAME;
use crate::{Error, Result};

const CGROUP_SYS_DIR: &str = "/sys/fs/cgroup";
pub const BPF_MESH_FS_DIR: &str = "/sys/fs/bpf/mesh";
pub const BPF_PROGRAM_INGRESS_PATH: &str = "/sys/fs/bpf/mesh/mesh_program_ingress";
const BPF_PROGRAM_CGROUP_CONNECT_V4: &str = "mesh_cni_cgroup_connect4";

#[derive(Clone)]
pub struct State {
    pub ebpf: Arc<Mutex<Ebpf>>,
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

        info!("ensuring mesh bpf directory");
        fs::create_dir_all(BPF_MESH_FS_DIR)?;
        ensure_ingress_program(&mut ebpf)?;

        let cgroup = File::open(CGROUP_SYS_DIR)?;
        attach_cgroup_connect_bpf_program(
            &mut ebpf,
            cgroup,
            BPF_PROGRAM_CGROUP_CONNECT_V4,
            CgroupAttachMode::Single,
        )?;
        Ok(Self {
            ebpf: Arc::new(Mutex::new(ebpf)),
        })
    }
    pub async fn take_map(&self, name: &str) -> Option<Map> {
        let ebpf = self.ebpf.lock().unwrap();
        let mut ebpf = ebpf;
        ebpf.take_map(name)
    }
}

fn ensure_ingress_program(ebpf: &mut Ebpf) -> Result<()> {
    if fs::exists(BPF_PROGRAM_INGRESS_PATH)? {
        return Ok(());
    }
    let ingress: &mut SchedClassifier = ebpf
        .program_mut(INGRESS_TC_NAME)
        .ok_or_else(|| {
            Error::EbpfProgramError(format!("failed to load program {INGRESS_TC_NAME}"))
        })?
        .try_into()?;

    if let Err(e) = ingress.load()
        && !matches!(e, aya::programs::ProgramError::AlreadyLoaded)
    {
        return Err(e.into());
    };

    info!("pinning ingress program to bpffs");
    ingress.pin(BPF_PROGRAM_INGRESS_PATH)?;

    Ok(())
}

fn attach_cgroup_connect_bpf_program<F: AsFd>(
    ebpf: &mut Ebpf,
    cgroup: F,
    name: &str,
    attach_mode: CgroupAttachMode,
) -> Result<CgroupSockAddrLinkId> {
    let program: &mut CgroupSockAddr = ebpf
        .program_mut(name)
        .ok_or_else(|| Error::EbpfProgramError(format!("failed to load program {name}")))?
        .try_into()?;
    if let Err(e) = program.load()
        && !matches!(e, aya::programs::ProgramError::AlreadyLoaded)
    {
        return Err(e.into());
    };
    Ok(program.attach(cgroup, attach_mode)?)
}
