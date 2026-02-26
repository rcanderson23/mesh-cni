use k8s_openapi::api::core::v1::{Namespace, Pod};
use kube::{Client, runtime::reflector::Store};
use mesh_cni_crds::v1alpha1::meshidentityslice::MeshIdentitySlice;

#[derive(Clone)]
pub struct Context {
    pub client: Client,
    pub pods: Store<Pod>,
    pub source_namespaces: Store<Namespace>,
    pub local_namespaces: Store<Namespace>,
    pub meshidentityslices: Store<MeshIdentitySlice>,
    pub cluster_name: String,
}
