mod context;
mod controller;
mod error;
mod runtime;

pub use error::{Error, Result};
pub use mesh_cni_crds::SERVICE_OWNER_LABEL;
pub use runtime::start_meshendpoint_gen_controller;

pub const MESH_SERVICE: &str = "mesh-cni.dev/multi-cluster";
