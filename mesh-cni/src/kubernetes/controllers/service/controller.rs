use std::net::IpAddr;
use std::{sync::Arc, time::Duration};

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::{EndpointConditions, EndpointSlice};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::Api;
use kube::api::{Patch, PatchParams};
use kube::core::Expression;
use kube::runtime::reflector::ObjectRef;
use kube::{ResourceExt, runtime::controller::Action};
use mesh_cni_common::KubeProtocol;
use tracing::{info, warn};

use crate::kubernetes::crds::meshendpoint::v1alpha1::{
    BackendPortMapping, MeshEndpoint, MeshEndpointSpec,
};
use crate::kubernetes::state::MultiClusterStore;
use crate::{Error, Result, kubernetes::controllers::service::state::State};

const SERVICE_OWNER_LABEL: &str = "kubernetes.io/service-name";
const MANANGER: &str = "service-meshendpoint-controller";

// Services passed into here should already have been checked for mesh annotation
pub async fn reconcile(service: Arc<Service>, ctx: Arc<State>) -> Result<Action> {
    info!(
        "started reconciling Service {}/{}",
        service.metadata.namespace.as_ref().unwrap(),
        service.metadata.name.as_ref().unwrap(),
    );

    let spec = generate_mesh_endpoint_spec(ctx.endpoint_slice_state.as_ref(), &service);
    let name = service.name_any();
    let Some(namespace) = service.namespace() else {
        warn!("failed to find namespace on Service {}", name);
        // TODO: consider changing to error
        return Ok(Action::await_change());
    };
    // check cached copy to save a network request
    //
    let cached = ctx
        .mesh_endpoint_state
        .get(&ObjectRef::new(&name).within(&namespace));

    if let Some(mep) = cached
        && mep.spec == spec
    {
        return Ok(Action::await_change());
    }

    info!("creating mesh endpoint");
    let mut mesh_endpoint = MeshEndpoint::new(&name, spec);
    mesh_endpoint.metadata.owner_references = Some(owner_references(&service));
    let api: Api<MeshEndpoint> = Api::namespaced(ctx.client.clone(), &namespace);
    let ssaply = PatchParams::apply(MANANGER).force();

    api.patch(&name, &ssaply, &Patch::Apply(mesh_endpoint))
        .await?;

    Ok(Action::await_change())
}

// TODO: fix error coditions and potentially make generic for all controllers
pub fn error_policy(_service: Arc<Service>, _error: &Error, _ctx: Arc<State>) -> Action {
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

fn endpoint_slices_owned_by_service<T: MultiClusterStore<EndpointSlice>>(
    store: &T,
    service: &Service,
) -> Vec<Arc<EndpointSlice>> {
    let selector = Expression::Equal(SERVICE_OWNER_LABEL.into(), service.name_any()).into();
    // Service is namespaced
    store.get_all_by_namespace_label(Some(&service.namespace().unwrap_or_default()), &selector)
}

fn endpoint_ready(ep_cond: &EndpointConditions) -> bool {
    (ep_cond.ready == Some(true) || ep_cond.ready.is_none()) && (ep_cond.terminating != Some(true))
}

fn generate_mesh_endpoint_spec<T: MultiClusterStore<EndpointSlice>>(
    store: &T,
    service: &Service,
) -> MeshEndpointSpec {
    let service_ips = service_ips_from_service(service);
    let service_names_ports_protocols = service_names_ports_protocols(service);

    let slices = endpoint_slices_owned_by_service(store, service);

    let mut backend_port_mappings = Vec::new();

    for slice in &slices {
        let backend_ips = backend_ips_from_ep_slice(slice);
        for ip in backend_ips {
            for (name, service_port, protocol) in &service_names_ports_protocols {
                let Some(backend_port) = backend_port_from_ep_slice(slice, name, *protocol) else {
                    continue;
                };

                backend_port_mappings.push(BackendPortMapping {
                    ip,
                    service_port: *service_port,
                    backend_port,
                    protocol: protocol.to_string(),
                });
            }
        }
    }

    MeshEndpointSpec {
        service_ips,
        backend_port_mappings,
    }
}

fn service_ips_from_service(service: &Service) -> Vec<IpAddr> {
    let mut result = Vec::new();
    if let Some(spec) = &service.spec
        && let Some(ips) = &spec.cluster_ips
    {
        for ip in ips {
            if let Ok(ip) = ip.parse() {
                result.push(ip);
            } else {
                warn!(
                    "failed to parse ClusterIP {} in Service {}/{}",
                    ip,
                    service.namespace().unwrap_or_default(),
                    service.name_any()
                )
            }
        }
    }
    result
}

fn backend_ips_from_ep_slice(slice: &EndpointSlice) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for endpoint in &slice.endpoints {
        if let Some(conditions) = &endpoint.conditions
            && endpoint_ready(conditions)
        {
            for ip in &endpoint.addresses {
                let Ok(ip) = ip.parse() else {
                    continue;
                };
                ips.push(ip);
            }
        }
    }
    ips
}

fn backend_port_from_ep_slice(
    slice: &EndpointSlice,
    name: &str,
    protocol: KubeProtocol,
) -> Option<u16> {
    let Some(ports) = &slice.ports else {
        return None;
    };
    for p in ports {
        if p.name.as_deref() == Some(name)
            && let Some(port) = p.port
            && kube_proto_from_str(&p.protocol) == protocol
        {
            return Some(port as u16);
        }
    }
    None
}

fn service_names_ports_protocols(service: &Service) -> Vec<(String, u16, KubeProtocol)> {
    let mut names = Vec::new();
    if let Some(spec) = &service.spec
        && let Some(service_ports) = &spec.ports
    {
        for sp in service_ports {
            let protocol = if let Some(protocol) = &sp.protocol
                && let Ok(protocol) = protocol.as_str().try_into()
            {
                protocol
            } else {
                continue;
            };
            if let Some(name) = &sp.name {
                names.push((name.clone(), sp.port as u16, protocol));
            } else {
                names.push((String::new(), sp.port as u16, protocol));
            }
        }
    }
    names
}

fn kube_proto_from_str(proto: &Option<String>) -> KubeProtocol {
    match proto {
        Some(p) => KubeProtocol::try_from(p.as_str()).unwrap_or_default(),
        None => KubeProtocol::Tcp,
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    use ahash::HashMap;
    use k8s_openapi::api::core::v1::{ServicePort, ServiceSpec};
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointPort};
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
