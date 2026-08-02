use k8s_openapi::api::core::v1::Pod;
use kube::{Client, runtime::reflector::Store};

pub struct Context<B> {
    pub pod_state: Store<Pod>,
    pub kube_client: Client,
    pub hostport_bpf_state: B,
}
