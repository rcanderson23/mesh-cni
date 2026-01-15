mod context;
mod controller;
mod error;
mod metrics;
mod utils;

pub use controller::start_service_controller;
pub use error::{Error, Result};
pub use mesh_cni_crds::SERVICE_OWNER_LABEL;

pub const MESH_SERVICE: &str = "io.cilium/global-service";
