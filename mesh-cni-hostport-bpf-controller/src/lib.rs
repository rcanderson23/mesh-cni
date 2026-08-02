mod context;
mod controller;
mod error;
mod runtime;
mod utils;

use ahash::HashMap;
pub use context::Context;
pub use error::{Error, Result};
use mesh_cni_ebpf_common::hostport::{HostPortKey, HostPortValue};
pub use runtime::start_hostport_bpf_service_controller;

pub trait HostPortWriter {
    fn upsert_hostport(&self, key: HostPortKey, value: HostPortValue) -> Result<()>;
    fn remove_hostport(&self, key: &HostPortKey) -> Result<()>;
}

pub trait HostPortReader {
    fn hostport_state(&self) -> Result<HashMap<HostPortKey, HostPortValue>>;
}

pub trait HostPortDataplane: HostPortWriter + HostPortReader {}
impl<T> HostPortDataplane for T where T: HostPortWriter + HostPortReader {}
