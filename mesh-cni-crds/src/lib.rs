use thiserror::Error;

pub mod v1alpha1;

use kube::CustomResourceExt;

pub const SERVICE_OWNER_LABEL: &str = "kubernetes.io/service-name";

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("yaml error: {0}")]
    YamlError(#[from] serde_yaml::Error),
}

pub fn crd_gen_meshendpoint() -> Result<()> {
    print!(
        "---\n{}",
        serde_yaml::to_string(&v1alpha1::meshendpoint::MeshEndpoint::crd())?
    );
    Ok(())
}

pub fn crd_gen_identity() -> Result<()> {
    print!(
        "---\n{}",
        serde_yaml::to_string(&v1alpha1::identity::Identity::crd())?
    );
    Ok(())
}

pub fn crd_gen_cluster() -> Result<()> {
    print!(
        "---\n{}",
        serde_yaml::to_string(&v1alpha1::cluster::Cluster::crd())?
    );
    Ok(())
}

pub fn crd_gen_all() -> Result<()> {
    let crds = vec![
        v1alpha1::meshendpoint::MeshEndpoint::crd(),
        v1alpha1::identity::Identity::crd(),
        v1alpha1::cluster::Cluster::crd(),
    ];
    for crd in crds {
        print!("---\n{}", serde_yaml::to_string(&crd)?);
    }
    Ok(())
}
