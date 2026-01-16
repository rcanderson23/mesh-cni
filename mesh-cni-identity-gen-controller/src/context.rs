use k8s_openapi::api::core::v1::Pod;
use kube::{Client, runtime::reflector::Store};
use mesh_cni_crds::v1alpha1::identity::Identity;

pub struct Context {
    pub client: Client,
    pub pods: Store<Pod>,
    pub identities: Store<Identity>,
}
