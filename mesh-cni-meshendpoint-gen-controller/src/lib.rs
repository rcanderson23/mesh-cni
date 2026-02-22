mod context;
mod controller;
mod error;
mod runtime;

pub use controller::LABEL_CLUSTER_OWNER;
pub use error::{Error, Result};
pub use mesh_cni_crds::SERVICE_OWNER_LABEL;
pub use runtime::start_meshendpoint_gen_controller;

pub const MESH_SERVICE: &str = "mesh-cni.dev/multi-cluster";
