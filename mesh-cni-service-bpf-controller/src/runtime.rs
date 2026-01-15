use std::{fmt::Debug, sync::Arc};

use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::core::{Expression, Selector};
use kube::runtime::reflector::{ReflectHandle, Store as KubeStore};
use kube::{Api, ResourceExt};
use serde::de::DeserializeOwned;
use tokio_util::sync::CancellationToken;
use tracing::info;

use mesh_cni_crds::v1alpha1::meshendpoint::MeshEndpoint;

use crate::controller::{error_policy, reconcile};
use crate::utils::shutdown;
use crate::{Context, MESH_SERVICE, MeshControllerExt, Result, ServiceBpfState};

pub async fn start_bpf_service_controller<B>(
    service_state: KubeStore<Service>,
    service_stream: ReflectHandle<Service>,
    endpoint_slice_state: KubeStore<EndpointSlice>,
    endpoint_slice_stream: ReflectHandle<EndpointSlice>,
    mesh_endpoint_state: KubeStore<MeshEndpoint>,
    service_bpf_state: B,
    cancel: CancellationToken,
) -> Result<()>
where
    B: ServiceBpfState + Clone + Send + Sync + 'static,
{
    let context = Context {
        service_state: service_state.clone(),
        endpoint_slice_state,
        mesh_endpoint_state,
        service_bpf_state,
    };

    info!("starting Services controller");
    kube::runtime::Controller::for_shared_stream(service_stream, service_state)
        .graceful_shutdown_on(shutdown(cancel))
        .owns_shared_stream(endpoint_slice_stream)
        .run(reconcile, error_policy::<Service, B>, Arc::new(context))
        .for_each(|_| async move {})
        .await;
    Ok(())
}

pub async fn start_bpf_meshendpoint_controller<K, B>(
    api: Api<K>,
    service_state: KubeStore<Service>,
    endpoint_slice_state: KubeStore<EndpointSlice>,
    mesh_endpoint_state: KubeStore<MeshEndpoint>,
    service_bpf_state: B,
    cancel: CancellationToken,
) -> Result<()>
where
    K: MeshControllerExt<B>,
    K: ResourceExt<DynamicType = ()>,
    K: DeserializeOwned + Clone + Sync + Debug + Send + 'static,
    B: ServiceBpfState + Clone + Send + Sync + 'static,
{
    let context = Context {
        service_state,
        endpoint_slice_state,
        mesh_endpoint_state,
        service_bpf_state,
    };

    let selector: Selector = Expression::NotEqual(MESH_SERVICE.into(), "true".into()).into();
    let watcher_config = kube::runtime::watcher::Config::default().labels_from(&selector);

    info!("starting controller for {}", K::kind(&()));
    kube::runtime::Controller::new(api, watcher_config)
        .graceful_shutdown_on(shutdown(cancel))
        .run(reconcile, error_policy::<K, B>, Arc::new(context))
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
    Ok(())
}
