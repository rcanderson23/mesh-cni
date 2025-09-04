use kube::CustomResource;
use kube::KubeSchema;
use serde::{Deserialize, Serialize};

pub const NAME_GROUP_MESHENDPOINT: &str = "meshendpoints.mesh-cni.dev";
pub mod v1alpha1 {

    use super::*;

    #[derive(
        CustomResource, KubeSchema, Serialize, Deserialize, Default, PartialEq, Eq, Clone, Debug,
    )]
    #[kube(
        group = "mesh-cni.dev",
        version = "v1alpha1",
        kind = "MeshEndpoint",
        derive = "Default",
        derive = "PartialEq"
    )]
    pub struct MeshEndpointSpec {
        pub service_ips: Vec<String>,
        pub port_mappings: Vec<PortMapping>,
    }

    #[derive(KubeSchema, Serialize, Deserialize, Default, PartialEq, Eq, Clone, Debug)]
    pub struct PortMapping {
        pub port: u16,
        pub target_port: u16,
        pub protocol: String,
    }
}
