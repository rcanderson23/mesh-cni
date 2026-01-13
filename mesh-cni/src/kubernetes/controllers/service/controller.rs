use std::{sync::Arc, time::Duration};

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::Api;
use kube::api::{DeleteParams, Patch, PatchParams};
use kube::core::{Expression, Selector, SelectorExt};
use kube::runtime::reflector::ObjectRef;
use kube::{ResourceExt, runtime::controller::Action};
use tracing::{Span, field, info, instrument, warn};

use crate::kubernetes::controllers::bpf_service::MESH_SERVICE;
use crate::kubernetes::controllers::metrics;
use crate::kubernetes::crds::meshendpoint::v1alpha1::{MeshEndpoint, generate_mesh_endpoint_spec};
use crate::{Error, Result, kubernetes::controllers::service::context::Context};

const MANANGER: &str = "service-meshendpoint-controller";

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
    //
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

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::kubernetes::crds::meshendpoint::v1alpha1::{
        BackendPortMapping, MeshEndpointSpec, generate_mesh_endpoint_spec,
    };
    use crate::kubernetes::service::SERVICE_OWNER_LABEL;
    use crate::kubernetes::state::MultiClusterStore;
    use ahash::HashMap;
    use k8s_openapi::api::core::v1::{ServicePort, ServiceSpec};
    use k8s_openapi::api::discovery::v1::{
        Endpoint, EndpointConditions, EndpointPort, EndpointSlice,
    };
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    use kube::api::ObjectMeta;
    use kube::core::SelectorExt;

    use super::*;

    impl<K> MultiClusterStore<K> for HashMap<String, Vec<K>>
    where
        K: k8s_openapi::Metadata + kube::Resource + Clone,
        K::DynamicType: std::hash::Hash + std::cmp::Eq + Clone,
    {
        fn get_from_cluster(&self, obj_ref: &ObjectRef<K>, cluster_name: &str) -> Option<Arc<K>> {
            let store = self.get(cluster_name)?;
            for v in store {
                if v.name_any() == obj_ref.name && v.namespace() == obj_ref.namespace {
                    return Some(Arc::new(v.clone()));
                }
            }
            None
        }

        fn get_all(&self, obj_ref: &ObjectRef<K>) -> Vec<Arc<K>> {
            let mut result = Vec::new();
            for (_, v) in self.iter() {
                for o in v {
                    if o.name_any() == obj_ref.name && o.namespace() == obj_ref.namespace {
                        result.push(Arc::new(o.clone()));
                    }
                }
            }
            result
        }

        fn get_all_by_namespace_label(
            &self,
            namespace: Option<&str>,
            selector: &kube::core::Selector,
        ) -> Vec<Arc<K>> {
            let mut result = Vec::new();
            for (_, v) in self.iter() {
                for o in v {
                    if o.namespace().as_deref() == namespace && selector.matches(o.labels()) {
                        result.push(Arc::new(o.clone()))
                    }
                }
            }
            result
        }
    }

    #[test]
    fn test_mesh_spec_gen() {
        let service_name: String = "test-service".into();
        let service_namespace: String = "test-service-ns".into();
        let service_ips: Vec<String> = vec!["10.96.0.128".into()];
        let service = Service {
            metadata: ObjectMeta {
                name: Some(service_name.clone()),
                namespace: Some(service_namespace.clone()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ips: Some(service_ips.clone()),
                ports: Some(vec![ServicePort {
                    name: Some("http".into()),
                    port: 80,
                    protocol: Some("TCP".into()),
                    target_port: Some(IntOrString::Int(8080)),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut ep_slice_store = HashMap::default();

        let mut slice_labels = BTreeMap::new();
        slice_labels.insert(SERVICE_OWNER_LABEL.into(), service_name.clone());
        ep_slice_store.insert(
            "cluster1".into(),
            vec![EndpointSlice {
                endpoints: vec![Endpoint {
                    addresses: vec!["10.244.0.10".into()],
                    conditions: Some(EndpointConditions {
                        ready: Some(true),
                        serving: Some(true),
                        terminating: Some(false),
                    }),
                    ..Default::default()
                }],
                metadata: ObjectMeta {
                    labels: Some(slice_labels),
                    namespace: Some(service_namespace),
                    ..Default::default()
                },
                ports: Some(vec![EndpointPort {
                    name: Some("http".into()),
                    port: Some(8080),
                    protocol: Some("TCP".into()),
                    ..Default::default()
                }]),
                ..Default::default()
            }],
        );

        let got = generate_mesh_endpoint_spec(&ep_slice_store, &service);

        let expected = MeshEndpointSpec {
            service_ips: vec![IpAddr::V4(Ipv4Addr::new(10, 96, 0, 128))],
            backend_port_mappings: vec![BackendPortMapping {
                ip: IpAddr::V4(Ipv4Addr::new(10, 244, 0, 10)),
                service_port: 80,
                backend_port: 8080,
                protocol: "TCP".into(),
            }],
        };
        assert_eq!(got, expected);
    }
}
