mod context;
mod controller;
mod error;
mod runtime;

pub use error::{Error, Result};
use ipnetwork::IpNetwork;
use mesh_cni_ebpf_common::route::RouteV4;
pub use runtime::start_vxlan_controller;

pub trait VxlanRemoteCidrsWriter {
    fn upsert_vxlan_remote_cidr(&self, key: IpNetwork, value: RouteV4) -> Result<()>;
    fn remove_vxlan_remote_cidr(&self, key: &IpNetwork) -> Result<()>;
}

pub trait VxlanRemoteCidrsReader {
    fn vxlan_remote_cidrs_state(&self) -> Result<ahash::HashMap<IpNetwork, RouteV4>>;
}

pub trait VxlanRemoteCidrsDataplane:
    VxlanRemoteCidrsWriter + VxlanRemoteCidrsReader + Send + Sync + 'static
{
}

impl<T> VxlanRemoteCidrsDataplane for T where
    T: VxlanRemoteCidrsWriter + VxlanRemoteCidrsReader + Send + Sync + 'static
{
}
