use k8s_openapi::api::{core::v1::Service, discovery::v1::EndpointSlice};
use kube::runtime::reflector::Store;
use mesh_cni_crds::v1alpha1::meshendpoint::MeshEndpoint;

use crate::ServiceBpfState;

pub struct Context<B>
where
    B: ServiceBpfState + Clone + Send + Sync + 'static,
{
    pub service_state: Store<Service>,
    pub endpoint_slice_state: Store<EndpointSlice>,
    pub mesh_endpoint_state: Store<MeshEndpoint>,
    pub service_bpf_state: B,
}
