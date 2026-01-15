use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector::Store;
use mesh_cni_ebpf_common::service::{EndpointValueV4, EndpointValueV6, ServiceKeyV4, ServiceKeyV6};

use crate::bpf::service::{BpfServiceEndpointState, ServiceEndpointBpfMap};
use crate::kubernetes::controllers::metrics::ControllerMetrics;
use mesh_cni_crds::v1alpha1::meshendpoint::MeshEndpoint;

pub struct Context<SE4, SE6>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
{
    pub metrics: ControllerMetrics,
    pub service_state: Store<Service>,
    pub endpoint_slice_state: Store<EndpointSlice>,
    pub mesh_endpoint_state: Store<MeshEndpoint>,
    pub service_bpf_state: BpfServiceEndpointState<SE4, SE6>,
}
