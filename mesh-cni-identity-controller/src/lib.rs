mod context;
mod controller;
mod error;
mod node;
mod pod;
mod runtime;

use aya::maps::LpmTrie;
use std::net::{Ipv4Addr, Ipv6Addr};
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

// #[derive(Clone, Debug, Hash, PartialEq, Eq)]
// pub enum IpNetwork {
//     V4(IpNetworkV4),
//     V6(IpNetworkV6),
// }
//
// #[derive(Clone, Debug, Hash, PartialEq, Eq)]
// pub struct IpNetworkV4 {
//     pub ip: Ipv4Addr,
//     pub mask: u32,
// }
//
// #[derive(Clone, Debug, Hash, PartialEq, Eq)]
// pub struct IpNetworkV6 {
//     pub ip: Ipv6Addr,
//     pub mask: u32,
// }
