mod context;
mod controller;
mod error;
mod identity;
mod runtime;
pub mod selector;

use std::sync::Arc;

pub use error::Error;
use kube::runtime::controller::Action;
use mesh_cni_ebpf_common::policy::{PolicyKey, PolicyValue};
pub use runtime::start_policy_controllers;

use crate::context::Context;

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) trait PolicyControllerExt<P: PolicyControllerBpf> {
    async fn reconcile(&self, ctx: Arc<Context<P>>) -> Result<Action>;
}

pub trait PolicyControllerBpf {
    fn update(&self, key: PolicyKey, value: PolicyValue) -> Result<()>;
    fn delete(&self, key: &PolicyKey) -> Result<()>;
}
