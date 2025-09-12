mod controller;
mod state;

use std::fmt::Debug;
use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::{core::v1::Service, discovery::v1::EndpointSlice};
use kube::{
    Api, ResourceExt,
    core::{Expression, Selector},
    runtime::{
        Controller,
        reflector::{ReflectHandle, Store as KubeStore},
        watcher::Config,
    },
};
use serde::de::DeserializeOwned;
use tokio_util::sync::CancellationToken;

use mesh_cni_common::service::{EndpointValueV4, EndpointValueV6, ServiceKeyV4, ServiceKeyV6};
use tracing::info;

use crate::{
    Result,
    bpf::service::{BpfServiceEndpointState, ServiceEndpointBpfMap},
    kubernetes::{
        controllers::bpf_service::{controller::MeshControllerExt, state::State},
        crds::meshendpoint::v1alpha1::MeshEndpoint,
    },
};

use controller::{error_policy, reconcile};

pub const MESH_SERVICE: &str = "mesh-cni.dev/multi-cluster";

pub async fn start_bpf_service_controller<SE4, SE6>(
    service_state: KubeStore<Service>,
    service_stream: ReflectHandle<Service>,
    endpoint_slice_state: KubeStore<EndpointSlice>,
    endpoint_slice_stream: ReflectHandle<EndpointSlice>,
    mesh_endpoint_state: KubeStore<MeshEndpoint>,
    service_bpf_state: BpfServiceEndpointState<SE4, SE6>,
    cancel: CancellationToken,
) -> Result<()>
where
    // K: MeshControllerExt<SE4, SE6>,
    // K: ResourceExt<DynamicType = ()>,
    // K: DeserializeOwned + Clone + Sync + Debug + Send + 'static,
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4> + Send + 'static,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6> + Send + 'static,
{
    let state = State {
        service_state: service_state.clone(),
        endpoint_slice_state,
        mesh_endpoint_state,
        service_bpf_state,
    };

    info!("starting Services controller");
    Controller::for_shared_stream(service_stream, service_state)
        .graceful_shutdown_on(crate::kubernetes::controllers::utils::shutdown(cancel))
        .owns_shared_stream(endpoint_slice_stream)
        .run(
            reconcile,
            error_policy::<Service, SE4, SE6>,
            Arc::new(state),
        )
        .for_each(|_| async move {})
        .await;
    Ok(())
}

pub async fn start_bpf_meshendpoint_controller<K, SE4, SE6>(
    api: Api<K>,
    service_state: KubeStore<Service>,
    endpoint_slice_state: KubeStore<EndpointSlice>,
    mesh_endpoint_state: KubeStore<MeshEndpoint>,
    service_bpf_state: BpfServiceEndpointState<SE4, SE6>,
    cancel: CancellationToken,
) -> Result<()>
where
    K: MeshControllerExt<SE4, SE6>,
    K: ResourceExt<DynamicType = ()>,
    K: DeserializeOwned + Clone + Sync + Debug + Send + 'static,
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4> + Send + 'static,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6> + Send + 'static,
{
    let state = State {
        service_state,
        endpoint_slice_state,
        mesh_endpoint_state,
        service_bpf_state,
    };

    let selector: Selector = Expression::NotEqual(MESH_SERVICE.into(), "true".into()).into();
    let watcher_config = Config::default().labels_from(&selector);

    info!("starting controller for {}", K::kind(&()));
    Controller::new(api, watcher_config)
        .graceful_shutdown_on(crate::kubernetes::controllers::utils::shutdown(cancel))
        .run(reconcile, error_policy::<K, SE4, SE6>, Arc::new(state))
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
    Ok(())
}
