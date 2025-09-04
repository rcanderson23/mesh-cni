pub mod meshendpoint;

use crate::Result;

use kube::CustomResourceExt;

pub fn crd_gen() -> Result<()> {
    let crds = vec![meshendpoint::v1alpha1::MeshEndpoint::crd()];
    for crd in crds {
        print!("---\n{}", serde_yaml::to_string(&crd)?);
    }
    Ok(())
}
