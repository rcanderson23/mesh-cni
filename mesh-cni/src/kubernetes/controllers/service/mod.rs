use std::sync::Arc;

use ahash::HashMap;
use futures::{StreamExt, future::Select};
use k8s_openapi::api::{
    core::v1::Service,
    discovery::v1::{EndpointConditions, EndpointSlice},
};
use kube::{
    Api, Client, ResourceExt,
    core::{Expression, Selector},
    runtime::{Controller, reflector::Store, watcher::Config},
};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Result,
    kubernetes::{
        controllers::service::state::State,
        crds::meshendpoint::v1alpha1::{MeshEndpoint, MeshEndpointSpec},
        create_store_and_subscriber, selector_matches,
        state::MultiClusterState,
    },
};

use crate::kubernetes::controllers::service::controller::{error_policy, reconcile};

mod controller;
mod state;

pub const MESH_SERVICE: &str = "mesh-cni.dev/multi-cluster-service";

pub async fn start_service_controller(
    client: Client,
    service_state: Arc<MultiClusterState<Service>>,
    endpoint_slice_state: Arc<MultiClusterState<EndpointSlice>>,
    cancel: CancellationToken,
) -> Result<()> {
    let service_api: Api<Service> = Api::all(client.clone());
    let mesh_ep_api: Api<MeshEndpoint> = Api::all(client.clone());

    let (mesh_endpoint_state, _) = create_store_and_subscriber(mesh_ep_api).await?;
    let state = State {
        client,
        service_state,
        endpoint_slice_state,
        mesh_endpoint_state,
    };

    let selector: Selector = Expression::Equal(MESH_SERVICE.into(), "true".into()).into();
    let watcher_config = Config::default().labels_from(&selector);

    info!("starting mesh service controller");
    Controller::new(service_api, watcher_config)
        .graceful_shutdown_on(crate::kubernetes::controllers::shutdown(cancel))
        .run(reconcile, error_policy, Arc::new(state))
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
    Ok(())
}
