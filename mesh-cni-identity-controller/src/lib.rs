mod context;
mod controller;
mod error;
mod node;
mod pod;
mod runtime;

use std::sync::Arc;

pub use error::Error;
use kube::runtime::controller::Action;
pub use runtime::start_identity_controllers;

use crate::context::Context;

pub type Result<T> = std::result::Result<T, Error>;

pub trait IdentityWriter {
    fn upsert_identity(&self, key: ipnetwork::IpNetwork, value: u32) -> Result<()>;
    fn remove_identity(&self, key: ipnetwork::IpNetwork) -> Result<()>;
}

pub trait IdentityReader {
    fn identity_state(&self) -> Result<Vec<(ipnetwork::IpNetwork, u32)>>;
}

pub trait IdentityDataplane: IdentityWriter + IdentityReader {}
impl<T> IdentityDataplane for T where T: IdentityWriter + IdentityReader {}

pub(crate) trait IdentityControllerExt {
    async fn reconcile<B: IdentityWriter>(&self, ctx: Arc<Context<B>>) -> Result<Action>;
}
