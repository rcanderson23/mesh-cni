mod context;
mod controller;
mod crds;
mod error;
mod runtime;

pub use crds::crd_gen;
pub use error::Error;
pub use runtime::start_identity_controllers;

pub type Result<T> = std::result::Result<T, Error>;
