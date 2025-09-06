use std::sync::Arc;

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector::Store;

use crate::kubernetes::{crds::meshendpoint::v1alpha1::MeshEndpoint, state::MultiClusterState};

pub(crate) struct State {
    pub client: kube::Client,
    pub service_state: Arc<MultiClusterState<Service>>,
    pub endpoint_slice_state: Arc<MultiClusterState<EndpointSlice>>,
    pub mesh_endpoint_state: Store<MeshEndpoint>,
}
