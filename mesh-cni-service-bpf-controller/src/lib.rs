mod context;
mod controller;
mod error;
mod metrics;
mod utils;

pub use context::Context;
pub use controller::{
    MeshControllerExt, SERVICE_OWNER_LABEL, start_bpf_meshendpoint_controller,
    start_bpf_service_controller,
};
pub use error::{Error, Result};
pub use metrics::ControllerMetrics;

pub const MESH_SERVICE: &str = "io.cilium/global-service";

pub trait ServiceBpfState {
    fn update(
        &self,
        key: mesh_cni_ebpf_common::service::ServiceKey,
        value: Vec<mesh_cni_ebpf_common::service::EndpointValue>,
    ) -> Result<()>;
    fn remove(&self, key: &mesh_cni_ebpf_common::service::ServiceKey) -> Result<()>;
}
