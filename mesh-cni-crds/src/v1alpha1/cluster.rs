use kube::{CustomResource, KubeSchema};
use serde::{Deserialize, Serialize};

pub const NAME_GROUP_CLUSTER: &str = "clusters.mesh-cni.dev";

// TODO: Consider re-adding a valuable status field
#[derive(CustomResource, KubeSchema, Serialize, Deserialize, Default, PartialEq, Clone, Debug)]
#[kube(
    group = "mesh-cni.dev",
    version = "v1alpha1",
    kind = "Cluster",
    derive = "Default",
    derive = "PartialEq"
)]
#[serde(rename_all = "camelCase")]
pub struct ClusterSpec {
    /// Name of the ConfigMap storing the kubeconfig for the cluster
    pub secret: SecretNameKey,
}

#[derive(KubeSchema, Serialize, Deserialize, Default, PartialEq, Clone, Debug)]
pub struct SecretNameKey {
    /// Name of the secret
    pub name: String,
    /// Key in secret to get kubeconfig
    pub key: Option<String>,
}
