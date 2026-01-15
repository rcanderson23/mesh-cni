use kube::CustomResource;
use kube::KubeSchema;
use schemars::json_schema;
use serde::{Deserialize, Serialize};

pub const NAME_GROUP_CLUSTER: &str = "clusters.mesh-cni.dev";

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use schemars::JsonSchema;

#[derive(
    CustomResource, KubeSchema, Serialize, Deserialize, Default, PartialEq, Eq, Clone, Debug,
)]
#[kube(
    group = "mesh-cni.dev",
    version = "v1alpha1",
    kind = "Cluster",
    derive = "Default",
    derive = "PartialEq"
)]
#[serde(rename_all = "camelCase")]
pub struct ClusterSpec {
    /// Unique ID for the cluster
    pub id: u32,
    /// Name of the ConfigMap storing the kubeconfig for the cluster
    pub config_map_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema)]
pub struct ClusterStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(schema_with = "conditions")]
    pub conditions: Vec<Condition>,
}

fn conditions(_: &mut schemars::generate::SchemaGenerator) -> schemars::Schema {
    json_schema!({
        "type": "array",
        "x-kubernetes-list-type": "map",
        "x-kubernetes-list-map-keys": ["type"],
        "items": {
            "type": "object",
            "properties": {
                "lastTransitionTime": { "format": "date-time", "type": "string" },
                "message": { "type": "string" },
                "observedGeneration": { "type": "integer", "format": "int64", "default": 0 },
                "reason": { "type": "string" },
                "status": { "type": "string" },
                "type": { "type": "string" }
            },
            "required": [
                "lastTransitionTime",
                "message",
                "reason",
                "status",
                "type"
            ],
        },
    })
}
