use std::collections::BTreeMap;
use std::fs::File;
use std::os::fd::AsFd;
use std::sync::Arc;

use aya::Ebpf;
use aya::maps::Map;
use aya::programs::cgroup_sock_addr::CgroupSockAddrLinkId;
use aya::programs::tc::SchedClassifierLinkId;
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use tokio::sync::Mutex;
use tracing::warn;

use crate::{Error, Result};

const NET_NS_DIR: &str = "/var/run/mesh/netns";
const CGROUP_SYS_DIR: &str = "/sys/fs/cgroup";
const INGRESS_TC_NAME: &str = "mesh_cni_ingress";
const EGRESS_TC_NAME: &str = "mesh_cni_egress";

type IfaceStore =
    Arc<Mutex<BTreeMap<(String, String), (SchedClassifierLinkId, SchedClassifierLinkId)>>>;

#[derive(Clone)]
pub struct State {
    pub ebpf: Arc<Mutex<Ebpf>>,
    // TODO: consider remvoing as these are likely unneeded
    ifaces: IfaceStore,
    _cgroup_addr_link_id: Arc<CgroupSockAddrLinkId>,
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
        let ifaces = BTreeMap::default();

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
        let cgroup = File::open(CGROUP_SYS_DIR)?;
        let _cgroup_addr_link_id = Arc::new(attach_cgroup_connect_bpf_program(
            &mut ebpf,
            cgroup,
            "mesh_cni_cgroup_connect4",
            CgroupAttachMode::Single,
        )?);
        Ok(Self {
            ebpf: Arc::new(Mutex::new(ebpf)),
            ifaces: Arc::new(Mutex::new(ifaces)),
            _cgroup_addr_link_id,
        })
    }
    pub async fn take_map(&self, name: &str) -> Option<Map> {
        let ebpf = self.ebpf.lock().await;
        let mut ebpf = ebpf;
        ebpf.take_map(name)
    }
    pub async fn insert_iface(
        &self,
        iface: String,
        netns: String,
        ingress_id: SchedClassifierLinkId,
        egress_id: SchedClassifierLinkId,
    ) {
        let mut ifaces = self.ifaces.lock().await;
        ifaces.insert((iface, netns), (ingress_id, egress_id));
    }
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
