use clap::{Parser, ValueEnum};

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum CrdKind {
    All,
    MeshEndpoint,
    Identity,
    CidrIdentity,
    Cluster,
}

#[derive(Parser, Debug)]
#[command(name = "mesh-cni-crds-gen")]
#[command(about = "Generate mesh-cni CRD YAML")]
struct Cli {
    /// CRD kind to generate.
    #[arg(long, value_enum, default_value_t = CrdKind::All)]
    kind: CrdKind,
}

fn main() -> mesh_cni_crds::Result<()> {
    let cli = Cli::parse();
    match cli.kind {
        CrdKind::All => mesh_cni_crds::crd_gen_all(),
        CrdKind::MeshEndpoint => mesh_cni_crds::crd_gen_meshendpoint(),
        CrdKind::Identity => mesh_cni_crds::crd_gen_identity(),
        CrdKind::CidrIdentity => mesh_cni_crds::crd_gen_cidridentity(),
        CrdKind::Cluster => mesh_cni_crds::crd_gen_cluster(),
    }
}
