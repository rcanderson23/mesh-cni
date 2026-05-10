use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

use anyhow::{Context, anyhow};
use aya::{
    Ebpf, EbpfLoader,
    programs::{
        CgroupAttachMode, CgroupSockAddr, SchedClassifier,
        links::{FdLink, LinkError, PinnedLink},
    },
};
use tracing::{error, info, warn};

use crate::{
    Result,
    bpf::{
        BPF_LINK_CGROUP_CONNECT_V4_PATH, BPF_MESH_LINKS_DIR, BPF_MESH_MAPS_DIR, BPF_MESH_PROG_DIR,
        BPF_PROGRAM_CGROUP_CONNECT_V4, BpfNamePath, HOSTPORT_MAPS_LIST, POLICY_MAPS_LIST,
        SERVICE_MAPS_LIST, TC_PROG_LIST, TC_VXLAN_PROG_LIST,
    },
    config::CniMode,
};

const CGROUP_SYS_DIR: &str = "/sys/fs/cgroup";

pub fn init_bpf(mode: &CniMode) -> Result<()> {
    ensure_pin_dirs()?;
    let mut ebpf = load_ebpf()?;

    info!("ensuring cgroupsockaddr program loaded and pinned");
    attach_cgroup_connect_bpf_program(&mut ebpf)?;

    for prog in TC_PROG_LIST {
        info!("ensuring {} program loaded and pinned", prog.name());
        ensure_tc_program(&mut ebpf, prog)?;
    }

    if matches!(mode, CniMode::Vxlan) {
        for prog in TC_VXLAN_PROG_LIST {
            info!("ensuring {} program loaded and pinned", prog.name());
            ensure_tc_program(&mut ebpf, prog)?;
        }
    }

    start_ebpf_logger(mode)?;

    Ok(())
}

fn load_ebpf() -> Result<Ebpf> {
    let mut loader = EbpfLoader::new();
    for map in SERVICE_MAPS_LIST
        .iter()
        .chain(POLICY_MAPS_LIST.iter())
        .chain(HOSTPORT_MAPS_LIST.iter())
    {
        loader.map_pin_path(map.name(), map.path());
    }

    let ebpf = loader.load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/mesh-ebpf"
    )))?;
    Ok(ebpf)
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

fn ensure_tc_program(ebpf: &mut Ebpf, prog_path_name: BpfNamePath) -> Result<()> {
    let prog: &mut SchedClassifier = ebpf
        .program_mut(prog_path_name.name())
        .ok_or_else(|| anyhow!("failed to get program {}", prog_path_name.name()))?
        .try_into()?;

    if let Err(e) = prog.load()
        && !matches!(e, aya::programs::ProgramError::AlreadyLoaded)
    {
        return Err(e.into());
    };

    let pin_path = prog_path_name.path();
    let temp_path = temp_pin_path(&pin_path)?;
    info!(path = %pin_path.display(), "pinning latest tc program to bpffs");
    let _ = fs::remove_file(&temp_path);
    if let Err(e) = prog.pin(&temp_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(e.into());
    }
    if let Err(e) = fs::rename(&temp_path, &pin_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(e.into());
    }

    Ok(())
}

fn temp_pin_path(final_path: &Path) -> Result<PathBuf> {
    let parent = final_path
        .parent()
        .ok_or_else(|| anyhow!("pin path {} has no parent directory", final_path.display()))?;
    let file_name = final_path
        .file_name()
        .ok_or_else(|| anyhow!("pin path {} has no file name", final_path.display()))?
        .to_string_lossy();

    Ok(parent.join(format!("{file_name}_tmp")))
}

fn replace_pinned_link(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    if !path.try_exists()? {
        return Ok(());
    }

    match PinnedLink::from_pin(path) {
        Ok(link) => {
            let _link = link.unpin()?;
            Ok(())
        }
        Err(LinkError::SyscallError(err))
            if err.io_error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn start_ebpf_logger(mode: &CniMode) -> Result<()> {
    let cgroup_prog = CgroupSockAddr::from_pin(
        BPF_PROGRAM_CGROUP_CONNECT_V4.path(),
        aya::programs::CgroupSockAddrAttachType::Connect4,
    )?;
    let info = cgroup_prog.info()?;
    start_ebpf_logger_from_prog_id(info.id())?;

    for prog in TC_PROG_LIST {
        let prog = SchedClassifier::from_pin(prog.path())?;
        let info = prog.info()?;
        start_ebpf_logger_from_prog_id(info.id())?;
    }

    if matches!(mode, CniMode::Vxlan) {
        for prog in TC_VXLAN_PROG_LIST {
            let prog = SchedClassifier::from_pin(prog.path())?;
            let info = prog.info()?;
            start_ebpf_logger_from_prog_id(info.id())?;
        }
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
    replace_pinned_link(BPF_LINK_CGROUP_CONNECT_V4_PATH)?;
    attach_and_pin_cgroup_link(program)?;

    let pin_path = BPF_PROGRAM_CGROUP_CONNECT_V4.path();
    let temp_path = temp_pin_path(&pin_path)?;
    let _ = fs::remove_file(&temp_path);
    if let Err(e) = program.pin(&temp_path) {
        let _ = fs::remove_file(&temp_path);
        error!("failed to pin {}", &temp_path.display());
        return Err(e.into());
    }
    if let Err(e) = fs::rename(&temp_path, &pin_path) {
        let _ = fs::remove_file(&temp_path);
        error!(
            "failed to rename {} to {}",
            &temp_path.display(),
            &pin_path.display()
        );
        return Err(e.into());
    }
    Ok(())
}

fn attach_and_pin_cgroup_link(program: &mut CgroupSockAddr) -> Result<()> {
    let cgroup = File::open(CGROUP_SYS_DIR)?;
    let link_id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .context("failed to attach cgroup")?;

    let link = program.take_link(link_id)?;
    let link: FdLink = link
        .try_into()
        .map_err(|e| anyhow!("failed to create fdlink from cgroup attachment link: {e}"))?;
    link.pin(BPF_LINK_CGROUP_CONNECT_V4_PATH)
        .context("failed to pin")?;

    Ok(())
}
