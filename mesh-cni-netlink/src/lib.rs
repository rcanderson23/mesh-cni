mod error;
mod handle;

pub use crate::{error::Error, handle::Netlink};

pub type Result<T> = std::result::Result<T, Error>;
