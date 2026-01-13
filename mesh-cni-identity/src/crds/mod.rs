pub mod identity;

use kube::CustomResourceExt;

use crate::Result;

pub fn crd_gen() -> Result<()> {
    let crds = vec![identity::v1alpha1::Identity::crd()];
    for crd in crds {
        print!("---\n{}", serde_yaml::to_string(&crd)?);
    }
    Ok(())
}
