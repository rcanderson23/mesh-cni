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
    Context, Result, SERVICE_OWNER_LABEL, ServiceBpfState,
    controller::{error_policy, reconcile},
    utils::shutdown,
};

pub async fn start_bpf_service_controller<B>(
    kube_client: Client,
    service_bpf_state: B,
    cancel: CancellationToken,
) -> Result<()>
where
    B: ServiceBpfState + Clone + Send + Sync + 'static,
{
    let service_api: Api<Service> = Api::all(kube_client.clone());
    let (service_state, service_subscriber) =
        create_store_and_touched_subscriber(service_api, Some(Duration::from_secs(30))).await?;

    let endpoint_slice_api: Api<EndpointSlice> = Api::all(kube_client.clone());
    let (endpoint_slice_state, endpoint_slice_subscriber) =
        create_store_and_touched_subscriber(endpoint_slice_api, Some(Duration::from_secs(30)))
            .await?;

    let mesh_endpoint_api = Api::all(kube_client.clone());
    let (mesh_endpoint_state, mesh_endpoint_subscriber) = create_store_and_touched_subscriber(
        mesh_endpoint_api.clone(),
        Some(Duration::from_secs(30)),
    )
    .await?;
    let context = Context {
        service_state: service_state.clone(),
        endpoint_slice_state,
        mesh_endpoint_state,
        service_bpf_state,
    };

    info!("Starting Services controller");
    Controller::for_shared_stream(service_subscriber, service_state)
        .graceful_shutdown_on(shutdown(cancel))
        .owns_shared_stream(endpoint_slice_subscriber)
        .watches_shared_stream(mesh_endpoint_subscriber, meshendpoint_to_service_mapper)
        .run(reconcile, error_policy::<B>, Arc::new(context))
        .for_each(|_| futures::future::ready(()))
        .await;
    Ok(())
}

fn meshendpoint_to_service_mapper(meshendpoint: Arc<MeshEndpoint>) -> Option<ObjectRef<Service>> {
    let namespace = meshendpoint.namespace()?;
    let service_name = meshendpoint.labels().get(SERVICE_OWNER_LABEL)?;
    Some(ObjectRef::new(service_name).within(&namespace))
}
