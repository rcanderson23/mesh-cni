use k8s_openapi::api::core::v1::Namespace;
use kube::runtime::reflector::Store;
use mesh_cni_crds::v1alpha1::identity::Identity;

use crate::IdentityBpfState;

pub struct Context<B: IdentityBpfState> {
    pub node_name: String,
    pub identity_store: Store<Identity>,
    pub namespace_store: Store<Namespace>,
    pub bpf_maps: B,
}
