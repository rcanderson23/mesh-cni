use k8s_openapi::api::core::v1::Node;
use kube::runtime::reflector::Store;
use rtnetlink::Handle;

pub struct Context {
    pub node_name: String,
    pub node_store: Store<Node>,
    pub handle: Handle,
    pub mesh_vxlan_ifindex: u32,
}
