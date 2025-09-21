use std::sync::Arc;

use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector::Store;

use crate::kubernetes::controllers::metrics::ControllerMetrics;
use crate::kubernetes::{crds::meshendpoint::v1alpha1::MeshEndpoint, state::MultiClusterState};

pub(crate) struct Context {
    pub metrics: ControllerMetrics,
    pub client: kube::Client,
    pub endpoint_slice_state: Arc<MultiClusterState<EndpointSlice>>,
    pub mesh_endpoint_state: Store<MeshEndpoint>,
}
