mod context;
mod controller;
mod error;
mod runtime;

pub use error::Error;
pub use runtime::start_identity_gen_controller;

pub type Result<T> = std::result::Result<T, Error>;
