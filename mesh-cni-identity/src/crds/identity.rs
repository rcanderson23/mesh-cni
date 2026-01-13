use kube::CustomResource;
use kube::KubeSchema;
use serde::{Deserialize, Serialize};

pub mod v1alpha1 {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(
        CustomResource, KubeSchema, Serialize, Deserialize, Default, PartialEq, Eq, Clone, Debug,
    )]
    #[kube(
        group = "mesh-cni.dev",
        version = "v1alpha1",
        kind = "Identity",
        derive = "Default",
        derive = "PartialEq",
        namespaced
    )]
    #[serde(rename_all = "camelCase")]
    pub struct IdentitySpec {
        pub namespace_labels: BTreeMap<String, String>,
        pub pod_labels: BTreeMap<String, String>,
        pub id: u32,
    }
}
