use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_openapi::{
    api::{core::v1::Service, discovery::v1::EndpointSlice},
    apimachinery::pkg::apis::meta::v1::OwnerReference,
};
use kube::{
    Api, Client, ResourceExt,
    api::{DeleteParams, Patch, PatchParams},
    core::{Expression, Selector, SelectorExt},
    runtime::{controller::Action, reflector::ObjectRef},
};
use mesh_cni_crds::v1alpha1::meshendpoint::{MeshEndpoint, generate_mesh_endpoint_spec};
use mesh_cni_k8s_utils::create_store_and_subscriber;
use tokio_util::sync::CancellationToken;
use tracing::{Span, field, info, instrument, warn};

use crate::{
    Error, MESH_SERVICE, Result, SERVICE_OWNER_LABEL, context::Context, metrics, utils::shutdown,
};

const MANANGER: &str = "service-meshendpoint-controller";

pub async fn start_service_controller(client: Client, cancel: CancellationToken) -> Result<()> {
    let service_api: Api<Service> = Api::all(client.clone());
    let endpoint_slice_api: Api<EndpointSlice> = Api::all(client.clone());
    let mesh_ep_api: Api<MeshEndpoint> = Api::all(client.clone());

    let (endpoint_slice_state, _endpoint_slice_subscriber) =
        create_store_and_subscriber(endpoint_slice_api.clone(), Some(Duration::from_secs(30)))
            .await?;
    let (mesh_endpoint_state, _) =
        create_store_and_subscriber(mesh_ep_api, Some(Duration::from_secs(30))).await?;
    let metrics = crate::metrics::ControllerMetrics::new("meshendpoint-services");
    let context = Context {
        metrics,
        client,
        endpoint_slice_state,
        mesh_endpoint_state,
    };

    info!("starting mesh service controller");
    kube::runtime::Controller::new(
        service_api,
        kube::runtime::watcher::Config::default().any_semantic(),
    )
    .graceful_shutdown_on(shutdown(cancel))
    .watches(
        endpoint_slice_api,
        kube::runtime::watcher::Config::default(),
        endpoint_slice_mapper,
    )
    .run(reconcile, error_policy, Arc::new(context))
    .filter_map(|x| async move { std::result::Result::ok(x) })
    .for_each(|_| futures::future::ready(()))
    .await;
    Ok(())
}

fn endpoint_slice_mapper(slice: EndpointSlice) -> Option<ObjectRef<Service>> {
    let namespace = slice.namespace()?;
    let service_name = slice.labels().get(SERVICE_OWNER_LABEL)?;
    Some(ObjectRef::new(service_name).within(&namespace))
}

// Services passed into here should already have been checked for mesh annotation
#[instrument(skip(ctx, service), fields(trace_id))]
pub async fn reconcile(service: Arc<Service>, ctx: Arc<Context>) -> Result<Action> {
    let trace_id = metrics::get_trace_id();
    if trace_id != opentelemetry::trace::TraceId::INVALID {
        Span::current().record("trace_id", field::display(&trace_id));
    }
    let _timer = ctx.metrics.count_and_measure(service.as_ref(), &trace_id);
    let name = service.name_any();
    let Some(ns) = service.namespace() else {
        warn!("failed to find namespace on Service {}", name);
        // TODO: consider changing to error
        return Ok(Action::await_change());
    };
    info!("started reconciling Service {}/{}", ns, name);

    let selector: Selector = Expression::NotEqual(MESH_SERVICE.into(), "true".into()).into();
    if selector.matches(service.annotations()) {
        if let Some(mesh) = ctx
            .mesh_endpoint_state
            .get(&ObjectRef::new(&name).within(&ns))
        {
            let api: Api<MeshEndpoint> = Api::namespaced(ctx.client.clone(), &ns);
            api.delete(&mesh.name_any(), &DeleteParams::default())
                .await?
                .map_left(|_| info!("deleting MeshEndpoint {}/{}", ns, name))
                .map_right(|o| {
                    if o.is_success() {
                        info!("deleted MeshEndpoint {}/{}", ns, name)
                    }
                });
        }
        return Ok(Action::await_change());
    }

    let spec = generate_mesh_endpoint_spec(&ctx.endpoint_slice_state, &service);
    // check cached copy to save a network request
    let cached = ctx
        .mesh_endpoint_state
        .get(&ObjectRef::new(&name).within(&ns));

    if let Some(mep) = cached
        && mep.spec == spec
    {
        return Ok(Action::await_change());
    }

    let mut mesh_endpoint = MeshEndpoint::new(&name, spec);
    mesh_endpoint.metadata.owner_references = Some(owner_references(&service));
    let api: Api<MeshEndpoint> = Api::namespaced(ctx.client.clone(), &ns);
    let ssapply = PatchParams::apply(MANANGER).force();

    dbg!(&mesh_endpoint);
    api.patch(&name, &ssapply, &Patch::Apply(mesh_endpoint))
        .await?;
    info!("created mesh endpoint {}/{}", ns, name);

    Ok(Action::await_change())
}

// TODO: fix error coditions and potentially make generic for all controllers
pub fn error_policy(service: Arc<Service>, error: &Error, ctx: Arc<Context>) -> Action {
    ctx.metrics.count_failure(service.as_ref(), error);
    Action::requeue(Duration::from_secs(5 * 60))
}

fn owner_references(service: &Service) -> Vec<OwnerReference> {
    vec![OwnerReference {
        api_version: "v1".into(),
        block_owner_deletion: Some(true),
        controller: Some(true),
        kind: "Service".into(),
        name: service.name_any(),
        uid: <Service as ResourceExt>::uid(service).unwrap_or_default(),
    }]
}
