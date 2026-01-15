mod context;
mod controller;
mod error;
mod runtime;
mod utils;

pub use context::Context;
pub use controller::{MeshControllerExt, SERVICE_OWNER_LABEL};
pub use error::{Error, Result};
use mesh_cni_ebpf_common::service::{EndpointValue, ServiceKey};
pub use runtime::{start_bpf_meshendpoint_controller, start_bpf_service_controller};

pub const MESH_SERVICE: &str = "mesh-cni.dev/multi-cluster";

pub trait ServiceBpfState {
    fn update(&self, key: ServiceKey, value: Vec<EndpointValue>) -> Result<()>;
    fn remove(&self, key: &ServiceKey) -> Result<()>;
}
