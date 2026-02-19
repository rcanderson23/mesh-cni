use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_openapi::api::{core::v1::Service, discovery::v1::EndpointSlice};
use kube::{
    Api, Client, ResourceExt,
    runtime::{Controller, reflector::ObjectRef},
};
use mesh_cni_crds::v1alpha1::meshendpoint::MeshEndpoint;
use mesh_cni_k8s_utils::create_store_and_touched_subscriber;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Result, SERVICE_OWNER_LABEL,
    context::Context,
    controller::{error_policy, reconcile},
};

pub async fn start_meshendpoint_gen_controller(
    local_client: Client,
    source_client: Client,
    cluster_name: String,
    cancel: CancellationToken,
) -> Result<()> {
    let service_api: Api<Service> = Api::all(local_client.clone());
    let endpoint_slice_api: Api<EndpointSlice> = Api::all(source_client.clone());
    let mesh_ep_api: Api<MeshEndpoint> = Api::all(local_client.clone());

    let (endpoint_slice_state, endpoint_slice_subscriber) = create_store_and_touched_subscriber(
        endpoint_slice_api.clone(),
        Some(Duration::from_secs(30)),
    )
    .await?;
    let (mesh_endpoint_state, mesh_endpoint_subscriber) =
        create_store_and_touched_subscriber(mesh_ep_api, Some(Duration::from_secs(30))).await?;
    let context = Context {
        client: local_client,
        endpoint_slice_state,
        mesh_endpoint_state,
        cluster_name,
    };

    let controller_config = kube::runtime::Config::default().concurrency(10);

    info!("starting mesh service controller");
    Controller::new(
        service_api,
        kube::runtime::watcher::Config::default().any_semantic(),
    )
    .with_config(controller_config)
    .graceful_shutdown_on(shutdown(cancel))
    .watches_shared_stream(endpoint_slice_subscriber, service_mapper)
    .watches_shared_stream(mesh_endpoint_subscriber, service_mapper)
    .run(reconcile, error_policy, Arc::new(context))
    .filter_map(|x| async move { std::result::Result::ok(x) })
    .for_each(|_| futures::future::ready(()))
    .await;
    Ok(())
}

fn service_mapper<K: ResourceExt>(k: Arc<K>) -> Option<ObjectRef<Service>> {
    let namespace = k.namespace()?;
    let service_name = k.labels().get(SERVICE_OWNER_LABEL)?;
    Some(ObjectRef::new(service_name).within(&namespace))
}

pub(crate) async fn shutdown(cancel: CancellationToken) {
    tokio::select! {
        _ = cancel.cancelled() => {}
    }
}
