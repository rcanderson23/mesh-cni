use std::{sync::Arc, time::Duration};

use k8s_openapi::{api::core::v1::Service, apimachinery::pkg::apis::meta::v1::OwnerReference};
use kube::{
    Api, ResourceExt,
    api::{DeleteParams, Patch, PatchParams},
    core::{Expression, Selector, SelectorExt},
    runtime::{controller::Action, reflector::ObjectRef},
};
use mesh_cni_crds::{
    SERVICE_OWNER_LABEL,
    v1alpha1::meshendpoint::{MeshEndpoint, generate_mesh_endpoint_spec},
};
use tracing::{error, info, instrument};

use crate::{Error, MESH_SERVICE, Result, context::Context};

const MANANGER: &str = "service-meshendpoint-controller";
const LABEL_CLUSTER_OWNER: &str = "mesh-cni.dev/cluster-owner";

#[instrument(skip(ctx, service), fields(trace_id))]
pub async fn reconcile(service: Arc<Service>, ctx: Arc<Context>) -> Result<Action> {
    reconcile_service(service, ctx).await
}

pub fn error_policy(service: Arc<Service>, error: &Error, _ctx: Arc<Context>) -> Action {
    let name = service.name_any();
    let ns = service.namespace().unwrap_or_default();
    error!(%error, "failed to reconcile Service {ns}/{name}");
    Action::requeue(Duration::from_secs(5))
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

async fn reconcile_service(service: Arc<Service>, ctx: Arc<Context>) -> Result<Action> {
    let name = service.name_any();
    let ns = service.namespace().ok_or(Error::InvalidResource)?;
    let mep_name = format!("{}-{}", name, ctx.cluster_name);

    info!("started reconciling Service {}/{}", ns, name);
    let selector: Selector = Expression::NotEqual(MESH_SERVICE.into(), "true".into()).into();
    if selector.matches(service.annotations()) {
        if let Some(mesh) = ctx
            .mesh_endpoint_state
            .get(&ObjectRef::new(&mep_name).within(&ns))
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
        .get(&ObjectRef::new(&mep_name).within(&ns));

    if let Some(mep) = cached
        && mep.spec == spec
    {
        return Ok(Action::await_change());
    }

    let mut mesh_endpoint = MeshEndpoint::new(&mep_name, spec);
    mesh_endpoint.metadata.owner_references = Some(owner_references(&service));
    let labels = mesh_endpoint.labels_mut();
    labels.insert(LABEL_CLUSTER_OWNER.to_string(), ctx.cluster_name.clone());
    labels.insert(SERVICE_OWNER_LABEL.to_string(), service.name_any());

    let api: Api<MeshEndpoint> = Api::namespaced(ctx.client.clone(), &ns);
    let ssapply = PatchParams::apply(MANANGER).force();

    api.patch(&mep_name, &ssapply, &Patch::Apply(mesh_endpoint))
        .await?;
    info!("updated mesh endpoint {}/{}", ns, name);

    Ok(Action::await_change())
}
