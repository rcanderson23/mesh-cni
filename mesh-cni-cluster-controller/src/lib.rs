mod context;
mod controller;
mod error;
mod runtime;

pub use error::Error;
pub use mesh_cni_crds::v1alpha1;
pub use runtime::start_cluster_controller;

pub type Result<T> = std::result::Result<T, Error>;
