use k8s_openapi::api::core::v1::Node;
use kube::runtime::reflector::Store;

pub struct Context<R> {
    pub node_name: String,
    pub node_store: Store<Node>,
    pub routes: R,
    pub vxlan_ifindex: u32,
}
