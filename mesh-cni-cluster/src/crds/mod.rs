pub mod cluster;

use kube::CustomResourceExt;

use crate::Result;

pub fn crd_gen() -> Result<()> {
    let crds = vec![cluster::v1alpha1::Cluster::crd()];
    for crd in crds {
        print!("---\n{}", serde_yaml::to_string(&crd)?);
    }
    Ok(())
}
