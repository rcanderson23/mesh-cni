use kube::CustomResource;
use kube::KubeSchema;
use serde::{Deserialize, Serialize};

pub const NAME_GROUP_MESHENDPOINT: &str = "meshendpoints.mesh-cni.dev";
pub mod v1alpha1 {

    use std::net::IpAddr;

    use super::*;

    #[derive(
        CustomResource, KubeSchema, Serialize, Deserialize, Default, PartialEq, Eq, Clone, Debug,
    )]
    #[kube(
        group = "mesh-cni.dev",
        version = "v1alpha1",
        kind = "MeshEndpoint",
        derive = "Default",
        derive = "PartialEq",
        namespaced
    )]
    pub struct MeshEndpointSpec {
        pub service_ips: Vec<IpAddr>,
        pub backend_port_mappings: Vec<BackendPortMapping>,
    }

    #[derive(KubeSchema, Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
    pub struct BackendPortMapping {
        pub ip: IpAddr,
        pub service_port: u16,
        pub backend_port: u16,
        pub protocol: String,
    }
}
