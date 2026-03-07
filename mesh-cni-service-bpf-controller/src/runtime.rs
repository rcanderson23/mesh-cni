use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_openapi::api::{core::v1::Service, discovery::v1::EndpointSlice};
use kube::{
    Api, Client, ResourceExt,
    runtime::{Config, Controller, reflector::ObjectRef},
};
use mesh_cni_crds::v1alpha1::meshendpoint::MeshEndpoint;
use mesh_cni_k8s_utils::create_store_and_touched_subscriber;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    Context, Result, SERVICE_OWNER_LABEL, ServiceBpfState,
    controller::{error_policy, reconcile, reconcile_all_nodeports, reconcile_nodeports},
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
    let context = Arc::new(Context {
        service_state: service_state.clone(),
        endpoint_slice_state,
        mesh_endpoint_state,
        service_bpf_state,
    });

    // initial reconcile against entire state in case of missed deletions while restarting
    reconcile_all_nodeports(&context)?;

    let svc_config = Config::default().concurrency(10);

    info!("Starting NodePort controller");
    let nodeport_context = context.clone();
    tokio::spawn(
        Controller::for_shared_stream(service_subscriber.clone(), service_state.clone())
            .with_config(svc_config.clone())
            .graceful_shutdown_on(shutdown(cancel.clone()))
            .run(reconcile_nodeports, error_policy::<B>, context.clone())
            .for_each(move |result| {
                let nodeport_context = nodeport_context.clone();
                async move {
                    match result {
                        Ok(_) => {}
                        Err(kube::runtime::controller::Error::ObjectNotFound(obj_ref)) => {
                            warn!(?obj_ref, "service no longer in local store; running global NodePort cleanup");
                            if let Err(err) = reconcile_all_nodeports(&nodeport_context) {
                                error!(%err, "failed to reconcile global NodePort state after ObjectNotFound");
                            }
                        }
                        Err(err) => {
                            warn!(%err, "NodePort reconcile stream error");
                        }
                    }
                }
            }),
    );

    // TODO: consider adding similar ObjectNotFound reconcile as nodeport controller
    info!("Starting Services controller");
    Controller::for_shared_stream(service_subscriber, service_state)
        .with_config(svc_config)
        .graceful_shutdown_on(shutdown(cancel))
        .owns_shared_stream(endpoint_slice_subscriber)
        .watches_shared_stream(mesh_endpoint_subscriber, meshendpoint_to_service_mapper)
        .run(reconcile, error_policy::<B>, context)
        .for_each(|_| futures::future::ready(()))
        .await;
    Ok(())
}

fn meshendpoint_to_service_mapper(meshendpoint: Arc<MeshEndpoint>) -> Option<ObjectRef<Service>> {
    let namespace = meshendpoint.namespace()?;
    let service_name = meshendpoint.labels().get(SERVICE_OWNER_LABEL)?;
    Some(ObjectRef::new(service_name).within(&namespace))
}
