mod context;
mod controller;
mod error;
mod runtime;
mod utils;

use ahash::HashMap;
pub use context::Context;
pub use controller::SERVICE_OWNER_LABEL;
pub use error::{Error, Result};
use mesh_cni_ebpf_common::service::{EndpointValue, ServiceKey};
pub use runtime::start_bpf_service_controller;

pub trait ServiceBpfState {
    fn update(&self, key: ServiceKey, value: Vec<EndpointValue>) -> Result<()>;
    fn remove(&self, key: &ServiceKey) -> Result<()>;
    fn state(&self) -> Result<HashMap<ServiceKey, Vec<EndpointValue>>>;
}
