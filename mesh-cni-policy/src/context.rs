use k8s_openapi::api::core::v1::{Namespace, Pod};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::runtime::reflector::Store;
use npa::AllowedTraffic;

use crate::Result;

pub trait NetworkPolicyAnalyzer {
    fn allowed_traffic(&self, pod: &Pod) -> Result<AllowedTraffic>;
}

pub struct Context<NPA: NetworkPolicyAnalyzer> {
    pub analyzer: NPA,
    pub pod_store: Store<Pod>,
    pub policy_store: Store<NetworkPolicy>,
    pub namespace_store: Store<Namespace>,
}
