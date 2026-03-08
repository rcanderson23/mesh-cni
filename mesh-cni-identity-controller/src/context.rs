use k8s_openapi::api::core::v1::{Namespace, Pod};
use kube::runtime::reflector::Store;
use mesh_cni_crds::v1alpha1::identity::Identity;

pub struct Context<B> {
    pub node_name: String,
    pub pod_store: Store<Pod>,
    pub identity_store: Store<Identity>,
    pub namespace_store: Store<Namespace>,
    pub bpf_maps: B,
}
