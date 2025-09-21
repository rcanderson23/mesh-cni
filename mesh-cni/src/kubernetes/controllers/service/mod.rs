mod context;
mod controller;

use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::{core::v1::Service, discovery::v1::EndpointSlice};
use kube::{
    Api, Client,
    runtime::{Controller, watcher::Config},
};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Result,
    kubernetes::{
        controllers::{
            metrics::ControllerMetrics,
            service::{
                context::Context,
                controller::{error_policy, reconcile},
            },
        },
        crds::meshendpoint::v1alpha1::MeshEndpoint,
        create_store_and_subscriber,
        state::MultiClusterState,
    },
};

pub async fn start_service_controller(
    client: Client,
    endpoint_slice_state: Arc<MultiClusterState<EndpointSlice>>,
    cancel: CancellationToken,
) -> Result<()> {
    let service_api: Api<Service> = Api::all(client.clone());
    let mesh_ep_api: Api<MeshEndpoint> = Api::all(client.clone());

    let (mesh_endpoint_state, _) = create_store_and_subscriber(mesh_ep_api).await?;
    let metrics = ControllerMetrics::new("meshendpoint-services");
    let context = Context {
        metrics,
        client,
        endpoint_slice_state,
        mesh_endpoint_state,
    };

    info!("starting mesh service controller");
    Controller::new(service_api, Config::default().any_semantic())
        .graceful_shutdown_on(crate::kubernetes::controllers::utils::shutdown(cancel))
        .run(reconcile, error_policy, Arc::new(context))
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
    Ok(())
}
