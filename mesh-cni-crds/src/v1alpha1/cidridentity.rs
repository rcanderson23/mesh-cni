use kube::{CustomResource, KubeSchema};
use mesh_cni_ebpf_common::IdentityId;
use serde::{Deserialize, Serialize};

pub const NAME_GROUP_CIDR_IDENTITY: &str = "cidridentities.mesh-cni.dev";

#[derive(
    CustomResource, KubeSchema, Serialize, Deserialize, Default, PartialEq, Eq, Clone, Debug,
)]
#[kube(
    group = "mesh-cni.dev",
    version = "v1alpha1",
    kind = "CIDRIdentity",
    derive = "Default",
    derive = "PartialEq"
)]
#[serde(rename_all = "camelCase")]
pub struct CidrIdentitySpec {
    /// Stable CIDR identity id. Unique within CIDRIdentity custom resources.
    pub id: IdentityId,
    /// Generated prefixes based on all network policies in the cluster and mapped to
    /// the id in the policy map
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cidr_prefixes: Vec<String>,
    /// Maps to the ipBlock configured in NetworkPolicy
    pub cidr: Option<String>,
    /// Maps to the except in an ipBlock configured in NetworkPolicy
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub except: Vec<String>,
}
