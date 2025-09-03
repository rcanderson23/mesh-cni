use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::{core::v1::Service, discovery::v1::EndpointSlice};
use kube::{
    Api, Client,
    runtime::{Controller, watcher::Config},
};
use tokio_util::sync::CancellationToken;

use crate::{
    Result,
    kubernetes::{controllers::service::state::State, state::MultiClusterState},
};

use crate::kubernetes::controllers::service::controller::{error_policy, reconcile};

mod controller;
mod state;

pub const MESH_SERVICE: &str = "mesh.cni/multi-cluster-service";

pub async fn start_service_controller(
    client: Client,
    service_state: Arc<MultiClusterState<Service>>,
    endpoint_slice_state: Arc<MultiClusterState<EndpointSlice>>,
    cancel: CancellationToken,
) -> Result<()> {
    let service_api: Api<Service> = Api::all(client.clone());
    let state = State {
        service_state,
        endpoint_slice_state,
    };

    Controller::new(service_api, Config::default().any_semantic())
        .graceful_shutdown_on(crate::kubernetes::controllers::shutdown(cancel))
        .run(reconcile, error_policy, Arc::new(state))
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
    Ok(())
}
