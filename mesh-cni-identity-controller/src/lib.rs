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

pub trait IdentityBpfState {
    fn update(&self, key: ipnetwork::IpNetwork, value: u32) -> Result<()>;
}

pub(crate) trait IdentityControllerExt {
    async fn reconcile<B: IdentityBpfState>(&self, ctx: Arc<Context<B>>) -> Result<Action>;
}
