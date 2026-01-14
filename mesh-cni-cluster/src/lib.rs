mod context;
mod controller;
mod crds;
mod error;
mod runtime;

pub use crds::cluster::v1alpha1;
pub use error::Error;
pub use runtime::start_cluster_controller;

pub type Result<T> = std::result::Result<T, Error>;
