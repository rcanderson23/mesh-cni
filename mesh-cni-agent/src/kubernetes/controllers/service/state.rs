use std::sync::Arc;

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;

use crate::kubernetes::state::MultiClusterState;

pub(crate) struct State {
    pub service_state: Arc<MultiClusterState<Service>>,
    pub endpoint_slice_state: Arc<MultiClusterState<EndpointSlice>>,
}
