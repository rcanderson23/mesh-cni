use k8s_openapi::api::core::v1::Node;
use kube::runtime::reflector::Store;

pub struct Context<D> {
    pub node_name: String,
    pub node_store: Store<Node>,
    pub vxlan_remote_cidrs: D,
}
