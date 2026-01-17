use anyhow::{Context as _, bail};
use aya_build::cargo_metadata::{self, Package};

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let packages: Vec<Package> = packages
        .into_iter()
        .filter(|cargo_metadata::Package { name, .. }| {
            name.as_str() == "mesh-cni-service-ebpf" || name.as_str() == "mesh-cni-policy-ebpf"
        })
        .collect();
    if packages.is_empty() {
        bail!("failed to find service or policy ebpf packages");
    }
    aya_build::build_ebpf(packages, aya_build::Toolchain::default())
}
