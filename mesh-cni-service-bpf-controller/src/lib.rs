mod context;
mod controller;
mod error;
mod runtime;
mod utils;

use std::sync::Arc;

use ahash::HashMap;
pub use context::Context;
pub use controller::SERVICE_OWNER_LABEL;
pub use error::{Error, Result};
use mesh_cni_ebpf_common::service::{
    EndpointValue, NodePortFrontendValue, NodePortKey, ServiceKey,
};
pub use runtime::start_bpf_service_controller;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum NodePortMapKey {
    V4(NodePortKey),
    V6(NodePortKey),
}

pub trait ServiceBpfState {
    fn update(&self, key: ServiceKey, value: Vec<EndpointValue>) -> Result<()>;
    fn remove(&self, key: &ServiceKey) -> Result<()>;
    fn state(&self) -> Result<HashMap<ServiceKey, Vec<EndpointValue>>>;
    fn update_nodeport(&self, key: NodePortMapKey, value: ServiceKey) -> Result<()>;
    fn remove_nodeport(&self, key: &NodePortMapKey) -> Result<()>;
    fn update_nodeport_policy(
        &self,
        key: NodePortMapKey,
        value: NodePortFrontendValue,
    ) -> Result<()>;
    fn remove_nodeport_policy(&self, key: &NodePortMapKey) -> Result<()>;
    fn nodeport_state(&self) -> Result<HashMap<NodePortMapKey, ServiceKey>>;
}

impl<T> ServiceBpfState for Arc<T>
where
    T: ServiceBpfState + ?Sized,
{
    fn update(&self, key: ServiceKey, value: Vec<EndpointValue>) -> Result<()> {
        (**self).update(key, value)
    }

    fn remove(&self, key: &ServiceKey) -> Result<()> {
        (**self).remove(key)
    }

    fn state(&self) -> Result<HashMap<ServiceKey, Vec<EndpointValue>>> {
        (**self).state()
    }

    fn update_nodeport(&self, key: NodePortMapKey, value: ServiceKey) -> Result<()> {
        (**self).update_nodeport(key, value)
    }

    fn remove_nodeport(&self, key: &NodePortMapKey) -> Result<()> {
        (**self).remove_nodeport(key)
    }

    fn update_nodeport_policy(&self, key: NodePortMapKey, value: NodePortFrontendValue) -> Result<()> {
        (**self).update_nodeport_policy(key, value)
    }

    fn remove_nodeport_policy(&self, key: &NodePortMapKey) -> Result<()> {
        (**self).remove_nodeport_policy(key)
    }

    fn nodeport_state(&self) -> Result<HashMap<NodePortMapKey, ServiceKey>> {
        (**self).nodeport_state()
    }
}
