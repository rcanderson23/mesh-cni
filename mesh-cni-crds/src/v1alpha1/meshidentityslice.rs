use std::{collections::BTreeMap, net::IpAddr};

use kube::{CustomResource, KubeSchema};
use serde::{Deserialize, Serialize};

pub const NAME_GROUP_MESH_IDENTITY_SLICE: &str = "meshidentityslices.mesh-cni.dev";

#[derive(
    CustomResource, KubeSchema, Serialize, Deserialize, Default, PartialEq, Eq, Clone, Debug,
)]
#[kube(
    group = "mesh-cni.dev",
    version = "v1alpha1",
    kind = "MeshIdentitySlice",
    derive = "Default",
    derive = "PartialEq",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct MeshIdentitySliceSpec {
    /// Source cluster that owns this mirrored identity slice
    pub cluster: String,
    /// Canonical pod labels matched by this identity slice
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pod_labels: BTreeMap<String, String>,
    /// Snapshot of namespace labels for namespaceSelector evaluation
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub namespace_labels: BTreeMap<String, String>,
    /// Backend pod endpoints for this identity slice
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<MeshIdentityEndpoint>,
}

#[derive(KubeSchema, Serialize, Deserialize, PartialEq, Eq, Clone, Debug, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct MeshIdentityEndpoint {
    /// Backend pod IP
    pub ip: IpAddr,
    /// Named ports declared by this pod endpoint
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named_ports: Vec<MeshIdentityNamedPort>,
}

#[derive(KubeSchema, Serialize, Deserialize, PartialEq, Eq, Clone, Debug, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct MeshIdentityNamedPort {
    /// Named port identifier
    pub name: String,
    /// Protocol ("TCP", "UDP", or "SCTP")
    pub protocol: String,
    /// Container port value
    pub port: u16,
}
