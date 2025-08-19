pub mod ip;
pub mod metrics;

use aya::Ebpf;
use aya::maps::HashMap;
use aya::programs::tc::SchedClassifierLinkId;
use aya::programs::{SchedClassifier, TcAttachType, tc};
use mesh_cni_common::{Ip, IpStateId};
use tokio::task::JoinError;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::agent::ip::IpState;
use crate::config::ControllerArgs;
use crate::kubernetes::pod::NamespacePodState;
use crate::{Error, Result};

// TODO: make this configurable?
const POD_IDENTITY_CAPACITY: usize = 1000;

pub async fn start(args: ControllerArgs, cancel: CancellationToken) -> Result<()> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/mesh-cni"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }
    let iface = &args.iface;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(iface);
    let _ingress_id =
        attach_tc_bpf_program(&mut ebpf, iface, "mesh_cni_ingress", TcAttachType::Ingress)?;
    let _egress_id =
        attach_tc_bpf_program(&mut ebpf, iface, "mesh_cni_egress", TcAttachType::Egress)?;

    let (pod_id_tx, pod_id_rx) = tokio::sync::mpsc::channel(POD_IDENTITY_CAPACITY);

    // TODO: configure this dynamically for all clusters configured in mesh
    let kube_client = kube::Client::try_default().await?;
    let ns_pod_state = NamespacePodState::try_new(kube_client, args.cluster_id, pod_id_tx).await?;
    let ns_pod_handle = ns_pod_state.start();

    let ip_to_id: HashMap<_, Ip, IpStateId> =
        HashMap::try_from(ebpf.map_mut("IP_IDENTITY").unwrap()).unwrap();
    let mut ip_state = IpState::new(pod_id_rx, ip_to_id);
    let ip_handle = ip_state.start();

    tokio::select! {
        _ = cancel.cancelled() => {},
        _ = ip_handle => {},
        _ = ns_pod_handle => {},
    }
    Ok(())
}

fn attach_tc_bpf_program(
    ebpf: &mut Ebpf,
    iface: &str,
    name: &str,
    attach_type: TcAttachType,
) -> Result<SchedClassifierLinkId> {
    let program: &mut SchedClassifier = ebpf
        .program_mut(name)
        .ok_or_else(|| Error::EbpfError(format!("failed to load program {name}")))?
        .try_into()?;
    program.load()?;
    Ok(program.attach(iface, attach_type)?)
}

fn _exit(task: &str, out: Result<Result<()>, JoinError>) {
    match out {
        Ok(Ok(_)) => {
            info!("{task} exited")
        }
        Ok(Err(e)) => {
            error!("{task} failed with error: {e}")
        }
        _ => {}
    }
}
