use k8s_openapi::api::{
    core::v1::{Namespace, Pod},
    networking::v1::NetworkPolicy,
};
use kube::runtime::reflector::Store;
use mesh_cni_crds::v1alpha1::identity::Identity;

use crate::PolicyControllerBpf;

#[allow(unused)]
pub struct Context<P: PolicyControllerBpf> {
    pub pod_store: Store<Pod>,
    pub policy_store: Store<NetworkPolicy>,
    pub namespace_store: Store<Namespace>,
    pub identity_store: Store<Identity>,
    pub policy_bpf_state: P,
}
