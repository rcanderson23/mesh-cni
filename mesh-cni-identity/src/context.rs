use k8s_openapi::api::core::v1::Pod;
use kube::Client;
use kube::runtime::reflector::Store;

use crate::crds::identity::v1alpha1::Identity;

pub struct Context {
    pub client: Client,
    pub pods: Store<Pod>,
    pub identities: Store<Identity>,
}
