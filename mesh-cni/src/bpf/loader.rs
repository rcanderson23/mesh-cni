use std::{
    fs::{self, File},
    io,
};

use anyhow::{anyhow, bail};
use aya::{
    Ebpf,
    programs::{CgroupAttachMode, CgroupSockAddr, SchedClassifier, links::FdLink},
};
use tracing::{error, info, warn};

use crate::{
    Result,
    bpf::{
        BPF_LINK_CGROUP_CONNECT_V4_PATH, BPF_MESH_FS_DIR, BPF_MESH_LINKS_DIR, BPF_MESH_MAPS_DIR,
        BPF_MESH_PROG_DIR, BPF_PROGRAM_CGROUP_CONNECT_V4, BPF_PROGRAM_EGRESS_TC,
        BPF_PROGRAM_INGRESS_TC, BPF_PROGRAM_NODEPORT_EGRESS_TC, BPF_PROGRAM_NODEPORT_INGRESS_TC,
        BPF_PROGRAM_VXLAN_NODE_INGRESS_TC, BPF_PROGRAM_VXLAN_VETH_EGRESS_TC, BpfNamePath,
        POLICY_MAPS_LIST, PROG_LIST, SERVICE_MAPS_LIST, VXLAN_MAPS_LIST, VXLAN_PROG_LIST,
    },
    config::CniMode,
};

const CGROUP_SYS_DIR: &str = "/sys/fs/cgroup";

pub fn init_bpf(mode: &CniMode) -> Result<()> {
    if pins_exist(mode)? {
        start_ebpf_logger(mode)?;

        return Ok(());
    }
    reset_pins()?;

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/mesh-ebpf"
    )))?;

    info!("ensuring cgroupsockaddr program loaded and pinned");
    attach_cgroup_connect_bpf_program(&mut ebpf)?;

    info!("ensuring ingress program loaded and pinned");
    ensure_tc_program(&mut ebpf, BPF_PROGRAM_INGRESS_TC)?;

    info!("ensuring egress program loaded and pinned");
    ensure_tc_program(&mut ebpf, BPF_PROGRAM_EGRESS_TC)?;

    info!("ensuring nodeport ingress program loaded and pinned");
    ensure_tc_program(&mut ebpf, BPF_PROGRAM_NODEPORT_INGRESS_TC)?;

    info!("ensuring nodeport egress program loaded and pinned");
    ensure_tc_program(&mut ebpf, BPF_PROGRAM_NODEPORT_EGRESS_TC)?;

    pin_maps(&mut ebpf, &SERVICE_MAPS_LIST)?;
    pin_maps(&mut ebpf, &POLICY_MAPS_LIST)?;

    if matches!(mode, CniMode::Vxlan) {
        pin_maps(&mut ebpf, &VXLAN_MAPS_LIST)?;

        info!("ensuring vxlan veth egress program loaded and pinned");
        ensure_tc_program(&mut ebpf, BPF_PROGRAM_VXLAN_VETH_EGRESS_TC)?;

        info!("ensuring vxlan node ingress program loaded and pinned");
        ensure_tc_program(&mut ebpf, BPF_PROGRAM_VXLAN_NODE_INGRESS_TC)?;
    }

    start_ebpf_logger(mode)?;

    Ok(())
}

fn pin_maps(ebpf: &mut Ebpf, map_list: &[BpfNamePath]) -> Result<()> {
    for map in map_list {
        if fs::exists(map.path())? {
            bail!("pinned object {} already exists", map.path());
        }
        let Some(m) = ebpf.map_mut(map.name()) else {
            bail!("map {} not found", map.name());
        };
        m.pin(map.path())?;
    }
    Ok(())
}

fn ensure_pin_dirs() -> Result<()> {
    info!("ensuring mesh bpf maps directory");
    fs::create_dir_all(BPF_MESH_MAPS_DIR)?;

    info!("ensuring mesh bpf prog directory");
    fs::create_dir_all(BPF_MESH_PROG_DIR)?;

    info!("ensuring mesh bpf links directory");
    fs::create_dir_all(BPF_MESH_LINKS_DIR)?;

    Ok(())
}

fn pins_exist(mode: &CniMode) -> Result<bool> {
    for map in SERVICE_MAPS_LIST.iter().chain(POLICY_MAPS_LIST.iter()) {
        if !fs::exists(map.path())? {
            return Ok(false);
        }
    }
    for prog in PROG_LIST {
        if !fs::exists(prog.path())? {
            return Ok(false);
        }
    }
    if matches!(mode, CniMode::Vxlan) {
        for map in VXLAN_MAPS_LIST {
            if !fs::exists(map.path())? {
                return Ok(false);
            }
        }
        for prog in VXLAN_PROG_LIST {
            if !fs::exists(prog.path())? {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

fn reset_pins() -> Result<()> {
    warn!("resetting pins, this is expected on first startup");
    if let Err(e) = fs::remove_dir_all(BPF_MESH_FS_DIR)
        && !matches!(e.kind(), io::ErrorKind::NotFound)
    {
        error!("failed to remove {}", BPF_MESH_FS_DIR);
        return Err(e.into());
    };

    ensure_pin_dirs()?;

    Ok(())
}

fn ensure_tc_program(ebpf: &mut Ebpf, prog_path_name: BpfNamePath) -> Result<()> {
    if fs::exists(prog_path_name.path())? {
        return Ok(());
    }
    let prog: &mut SchedClassifier = ebpf
        .program_mut(prog_path_name.name())
        .ok_or_else(|| anyhow!("failed to get program {}", prog_path_name.name()))?
        .try_into()?;

    if let Err(e) = prog.load()
        && !matches!(e, aya::programs::ProgramError::AlreadyLoaded)
    {
        return Err(e.into());
    };

    if !fs::exists(prog_path_name.path())? {
        info!("pinning program to bpffs");
        prog.pin(prog_path_name.path())?;
    }

    Ok(())
}

fn start_ebpf_logger(mode: &CniMode) -> Result<()> {
    let cgroup_prog = CgroupSockAddr::from_pin(
        BPF_PROGRAM_CGROUP_CONNECT_V4.path(),
        aya::programs::CgroupSockAddrAttachType::Connect4,
    )?;
    let info = cgroup_prog.info()?;
    start_ebpf_logger_from_prog_id(info.id())?;

    let ingress = SchedClassifier::from_pin(BPF_PROGRAM_INGRESS_TC.path())?;
    let info = ingress.info()?;
    start_ebpf_logger_from_prog_id(info.id())?;

    let egress = SchedClassifier::from_pin(BPF_PROGRAM_EGRESS_TC.path())?;
    let info = egress.info()?;
    start_ebpf_logger_from_prog_id(info.id())?;

    let nodeport_ingress = SchedClassifier::from_pin(BPF_PROGRAM_NODEPORT_INGRESS_TC.path())?;
    let info = nodeport_ingress.info()?;
    start_ebpf_logger_from_prog_id(info.id())?;

    let nodeport_egress = SchedClassifier::from_pin(BPF_PROGRAM_NODEPORT_EGRESS_TC.path())?;
    let info = nodeport_egress.info()?;
    start_ebpf_logger_from_prog_id(info.id())?;

    if matches!(mode, CniMode::Vxlan) {
        let vxlan_veth_egress = SchedClassifier::from_pin(BPF_PROGRAM_VXLAN_VETH_EGRESS_TC.path())?;
        let info = vxlan_veth_egress.info()?;
        start_ebpf_logger_from_prog_id(info.id())?;

        let vxlan_node_ingress =
            SchedClassifier::from_pin(BPF_PROGRAM_VXLAN_NODE_INGRESS_TC.path())?;
        let info = vxlan_node_ingress.info()?;
        start_ebpf_logger_from_prog_id(info.id())?;
    }

    Ok(())
}

fn start_ebpf_logger_from_prog_id(program_id: u32) -> Result<()> {
    let logger = match aya_log::EbpfLogger::init_from_id(program_id) {
        Ok(l) => l,
        Err(e) => {
            warn!(%e, "unable to start ebpf logger from program");
            return Ok(());
        }
    };
    let mut logger =
        tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
    tokio::spawn(async move {
        loop {
            let mut guard = logger.readable_mut().await.unwrap();
            guard.get_inner_mut().flush();
            guard.clear_ready();
        }
    });
    Ok(())
}

fn attach_cgroup_connect_bpf_program(ebpf: &mut Ebpf) -> Result<()> {
    let program: &mut CgroupSockAddr = ebpf
        .program_mut(BPF_PROGRAM_CGROUP_CONNECT_V4.name())
        .ok_or_else(|| {
            anyhow!(
                "failed to load program {}",
                BPF_PROGRAM_CGROUP_CONNECT_V4.name()
            )
        })?
        .try_into()?;
    if let Err(e) = program.load()
        && !matches!(e, aya::programs::ProgramError::AlreadyLoaded)
    {
        return Err(e.into());
    };
    let cgroup = File::open(CGROUP_SYS_DIR)?;
    let link_id = program.attach(cgroup, CgroupAttachMode::Single)?;
    program.pin(BPF_PROGRAM_CGROUP_CONNECT_V4.path())?;

    let link = program.take_link(link_id)?;
    let link: FdLink = link
        .try_into()
        .map_err(|e| anyhow!("failed to create fdlink from cgroup attachment link: {e}"))?;
    link.pin(BPF_LINK_CGROUP_CONNECT_V4_PATH)?;

    Ok(())
}
