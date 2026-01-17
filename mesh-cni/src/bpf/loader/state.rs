use std::{
    fs::{self, File},
    io,
};

use aya::{
    Ebpf,
    programs::{CgroupAttachMode, CgroupSockAddr, SchedClassifier, links::FdLink},
};
use tracing::{error, info, warn};

use crate::{
    Error, Result,
    bpf::{
        BPF_LINK_CGROUP_CONNECT_V4_PATH, BPF_MESH_FS_DIR, BPF_MESH_LINKS_DIR, BPF_MESH_MAPS_DIR,
        BPF_MESH_PROG_DIR, BPF_PROGRAM_CGROUP_CONNECT_V4, BPF_PROGRAM_INGRESS_TC, BpfNamePath,
        POLICY_MAPS_LIST, PROG_LIST, SERVICE_MAPS_LIST,
    },
};

const CGROUP_SYS_DIR: &str = "/sys/fs/cgroup";

#[derive(Clone)]
pub struct State;

impl State {
    pub fn try_new() -> Result<State> {
        if pins_exist()? {
            start_ebpf_logger()?;

            return Ok(Self);
        }
        reset_pins()?;

        let mut service_ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/mesh-cni-service"
        )))?;

        info!("ensuring cgroupsockaddr program loaded and pinned");
        attach_cgroup_connect_bpf_program(&mut service_ebpf)?;

        pin_maps(&mut service_ebpf, &SERVICE_MAPS_LIST)?;

        let mut policy_ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/mesh-cni-policy"
        )))?;

        info!("ensuring ingress program loaded and pinned");
        ensure_ingress_program(&mut policy_ebpf)?;

        pin_maps(&mut policy_ebpf, &POLICY_MAPS_LIST)?;

        start_ebpf_logger()?;
        Ok(Self)
    }
}

fn pin_maps(ebpf: &mut Ebpf, map_list: &[BpfNamePath]) -> Result<()> {
    for map in map_list {
        if fs::exists(map.path())? {
            return Err(Error::PinExists { path: map.path() });
        }
        let Some(m) = ebpf.map_mut(map.name()) else {
            return Err(Error::MapNotFound {
                name: map.name().to_string(),
            });
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

fn pins_exist() -> Result<bool> {
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

fn ensure_ingress_program(ebpf: &mut Ebpf) -> Result<()> {
    if fs::exists(BPF_PROGRAM_INGRESS_TC.path())? {
        return Ok(());
    }
    let ingress: &mut SchedClassifier = ebpf
        .program_mut(BPF_PROGRAM_INGRESS_TC.name())
        .ok_or_else(|| {
            Error::EbpfProgramError(format!(
                "failed to get program {}",
                BPF_PROGRAM_INGRESS_TC.name()
            ))
        })?
        .try_into()?;

    if let Err(e) = ingress.load()
        && !matches!(e, aya::programs::ProgramError::AlreadyLoaded)
    {
        return Err(e.into());
    };

    if !fs::exists(BPF_PROGRAM_INGRESS_TC.path())? {
        info!("pinning ingress program to bpffs");
        ingress.pin(BPF_PROGRAM_INGRESS_TC.path())?;
    }

    Ok(())
}

fn start_ebpf_logger() -> Result<()> {
    let cgroup_prog = CgroupSockAddr::from_pin(
        BPF_PROGRAM_CGROUP_CONNECT_V4.path(),
        aya::programs::CgroupSockAddrAttachType::Connect4,
    )?;
    let info = cgroup_prog.info()?;
    start_ebpf_logger_from_prog_id(info.id())?;

    let ingress = SchedClassifier::from_pin(BPF_PROGRAM_INGRESS_TC.path())?;
    let info = ingress.info()?;
    start_ebpf_logger_from_prog_id(info.id())?;

    Ok(())
}

fn start_ebpf_logger_from_prog_id(program_id: u32) -> Result<()> {
    let logger = aya_log::EbpfLogger::init_from_id(program_id)?;
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
            Error::EbpfProgramError(format!(
                "failed to load program {}",
                BPF_PROGRAM_CGROUP_CONNECT_V4.name()
            ))
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
    let link: FdLink = link.try_into().map_err(|e| {
        Error::Other(format!(
            "failed to create fdlink from cgroup attachment link: {e}"
        ))
    })?;
    link.pin(BPF_LINK_CGROUP_CONNECT_V4_PATH)?;

    Ok(())
}
