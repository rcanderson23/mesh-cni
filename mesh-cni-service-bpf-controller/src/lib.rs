mod context;
mod controller;
mod error;
mod runtime;
mod utils;

use ahash::HashMap;
pub use context::Context;
pub use controller::SERVICE_OWNER_LABEL;
pub use error::{Error, Result};
use mesh_cni_ebpf_common::service::{EndpointValue, NodePortKey, ServiceKey};
pub use runtime::start_bpf_service_controller;

pub trait ServiceWriter {
    fn upsert_service(&self, key: ServiceKey, value: Vec<EndpointValue>) -> Result<()>;
    fn remove_service(&self, key: &ServiceKey) -> Result<()>;
}

pub trait NodePortWriter {
    fn upsert_nodeport(&self, key: NodePortKey, service_key: ServiceKey) -> Result<()>;
    fn remove_nodeport(&self, key: &NodePortKey) -> Result<()>;
}

pub trait ServiceReader {
    fn service_state(&self) -> Result<HashMap<ServiceKey, Vec<EndpointValue>>>;
}

pub trait NodePortReader {
    fn nodeport_state(&self) -> Result<HashMap<NodePortKey, ServiceKey>>;
}

pub trait ServiceDataplane:
    ServiceWriter + NodePortWriter + ServiceReader + NodePortReader
{
}
impl<T> ServiceDataplane for T where
    T: ServiceWriter + NodePortWriter + ServiceReader + NodePortReader
{
}
