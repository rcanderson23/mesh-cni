mod context;
mod controller;
mod error;
mod namespace;
mod networkpolicy;
mod runtime;

pub use error::Error;
pub use runtime::start_identity_gen_controller;

pub type Result<T> = std::result::Result<T, Error>;
