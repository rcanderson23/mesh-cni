use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::{Client, runtime::reflector::Store};
use mesh_cni_crds::v1alpha1::{cidridentity::CIDRIdentity, identity::Identity};

pub struct Context {
    pub client: Client,
    pub pods: Store<Pod>,
    pub identities: Store<Identity>,
    pub network_policies: Store<NetworkPolicy>,
    pub cidr_identities: Store<CIDRIdentity>,
}
