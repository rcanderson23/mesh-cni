use aya::Ebpf;
use aya::programs::tc::SchedClassifierLinkId;
use aya::programs::{SchedClassifier, TcAttachType, tc};

use crate::{Error, Result};

fn _attach_ebpf_to_iface(iface: &str) -> Result<()> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/mesh-cni"
    )))?;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(iface);
    let _ingress_id = attach_tc_bpf_program(
        &mut ebpf,
        iface,
        "homelab_cni_ingress",
        TcAttachType::Ingress,
    )?;
    let _egress_id =
        attach_tc_bpf_program(&mut ebpf, iface, "homelab_cni_egress", TcAttachType::Egress)?;
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
        .ok_or_else(|| Error::Ebpf(format!("failed to load program {name}")))?
        .try_into()?;
    program.load()?;
    Ok(program.attach(iface, attach_type)?)
}
