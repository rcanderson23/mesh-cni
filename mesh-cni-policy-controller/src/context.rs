use k8s_openapi::api::{
    core::v1::{Namespace, Pod},
    networking::v1::NetworkPolicy,
};
use kube::runtime::reflector::Store;

#[allow(unused)]
pub struct Context {
    pub pod_store: Store<Pod>,
    pub policy_store: Store<NetworkPolicy>,
    pub namespace_store: Store<Namespace>,
}
