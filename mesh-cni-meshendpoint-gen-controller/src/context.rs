use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector::Store;
use mesh_cni_crds::v1alpha1::meshendpoint::MeshEndpoint;

pub(crate) struct Context {
    pub client: kube::Client,
    pub endpoint_slice_state: Store<EndpointSlice>,
    pub mesh_endpoint_state: Store<MeshEndpoint>,
    pub cluster_name: String,
}
