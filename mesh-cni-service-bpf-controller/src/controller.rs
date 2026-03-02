use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use ahash::{HashMap, HashSet};
use k8s_openapi::api::{
    core::v1::Service,
    discovery::v1::{EndpointConditions, EndpointSlice},
};
use kube::{Resource, ResourceExt, runtime::controller::Action};
use mesh_cni_crds::v1alpha1::meshendpoint::{
    MeshEndpoint, coalesce_mesh_endpoints, generate_mesh_endpoint_spec, service_ips_from_service,
};
use mesh_cni_ebpf_common::{
    KubeProtocol,
    service::{EndpointValue, NodePortFrontendValue, NodePortKey, ServiceKey},
};
use mesh_cni_meshendpoint_gen_controller::ANNOTATION_MESH_SERVICE;
use tracing::{error, info, warn};

use crate::{Context, Error, NodePortMapKey, Result, ServiceBpfState};

const DEFAULT_REQUEUE_DURATION: Duration = Duration::from_secs(300);
const ERROR_REQUEUE_DURATION: Duration = Duration::from_secs(300);
const MISSING_MESH_ENDPOINT_REQUEUE_DURATION: Duration = Duration::from_secs(5);
pub const SERVICE_OWNER_LABEL: &str = "kubernetes.io/service-name";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExternalTrafficPolicy {
    Cluster,
    Local,
}

pub async fn reconcile<B>(service: Arc<Service>, ctx: Arc<Context<B>>) -> Result<Action>
where
    B: ServiceBpfState,
{
    let ns = service
        .namespace()
        .ok_or_else(|| Error::ReconcileMissingPrecondition("missing namespace".into()))?;
    let ns_name = format!("{}/{}", ns, service.name_any());
    info!("started reconciling Service {}", ns_name);

    if is_meshed_service(&service) {
        reconcile_multi_cluster_service(service, ctx).await
    } else {
        reconcile_local_service(service, ctx).await
    }
}

pub async fn reconcile_local_service<B>(
    service: Arc<Service>,
    ctx: Arc<Context<B>>,
) -> Result<Action>
where
    B: ServiceBpfState,
{
    let mut desired = generate_desired_service_pairs(&service, &ctx);
    let external_traffic_policy = external_traffic_policy(&service);
    let local_nodeport_services = filter_colliding_local_nodeport_services(
        &service,
        &desired,
        generate_local_nodeport_service_pairs(&service, &ctx),
    );
    desired.extend(local_nodeport_services.clone());
    let current = ctx.service_bpf_state.state()?;
    let is_deletion = service.meta().deletion_timestamp.is_some();
    let (keys_to_remove, entries_to_upsert) =
        diff_service_reconcile_actions(&service, &current, &desired, is_deletion);

    for key in keys_to_remove {
        ctx.service_bpf_state.remove(&key)?;
    }

    for (key, endpoints) in entries_to_upsert {
        ctx.service_bpf_state.update(key, endpoints)?;
    }
    reconcile_nodeport(
        &service,
        &ctx,
        &desired,
        &local_nodeport_services,
        external_traffic_policy,
        is_deletion,
    )?;

    Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
}

pub async fn reconcile_multi_cluster_service<B>(
    service: Arc<Service>,
    ctx: Arc<Context<B>>,
) -> Result<Action>
where
    B: ServiceBpfState,
{
    let mut desired = generate_service_pairs_from_meps(&service, &ctx);
    let current = ctx.service_bpf_state.state()?;
    let is_deletion = service.meta().deletion_timestamp.is_some();
    let mesh_endpoint_count = mesh_endpoint_count_for_service(&service, &ctx);
    let service_owned_key_count = service_owned_keys(&service, &current).len();

    if should_preserve_current_backends(
        is_deletion,
        desired.is_empty(),
        mesh_endpoint_count,
        service_owned_key_count,
    ) {
        info!(
            service = %service.name_any(),
            namespace = service.namespace().unwrap_or_default(),
            "no MeshEndpoints available yet for multi-cluster Service; keeping existing backends"
        );
        return Ok(Action::requeue(MISSING_MESH_ENDPOINT_REQUEUE_DURATION));
    }
    let external_traffic_policy = external_traffic_policy(&service);
    let local_nodeport_services = filter_colliding_local_nodeport_services(
        &service,
        &desired,
        generate_local_nodeport_service_pairs(&service, &ctx),
    );
    desired.extend(local_nodeport_services.clone());

    let (keys_to_remove, entries_to_upsert) =
        diff_service_reconcile_actions(&service, &current, &desired, is_deletion);

    for key in keys_to_remove {
        ctx.service_bpf_state.remove(&key)?;
    }

    for (key, endpoints) in entries_to_upsert {
        ctx.service_bpf_state.update(key, endpoints)?;
    }
    reconcile_nodeport(
        &service,
        &ctx,
        &desired,
        &local_nodeport_services,
        external_traffic_policy,
        is_deletion,
    )?;

    Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
}

pub fn error_policy<B>(_service: Arc<Service>, error: &Error, _ctx: Arc<Context<B>>) -> Action
where
    B: ServiceBpfState,
{
    error!("error occurred: {}", error);
    Action::requeue(ERROR_REQUEUE_DURATION)
}

fn generate_desired_service_pairs<B: ServiceBpfState>(
    service: &Service,
    ctx: &Context<B>,
) -> HashMap<ServiceKey, Vec<EndpointValue>> {
    let service_ips = service_ips_from_service(service);
    let spec = generate_mesh_endpoint_spec(&ctx.endpoint_slice_state, service);
    let mesh_endpoint = MeshEndpoint::new("dummy", spec);
    mesh_endpoint.generate_bpf_service_endpoints(&service_ips)
}

fn generate_service_pairs_from_meps<B: ServiceBpfState>(
    service: &Service,
    ctx: &Context<B>,
) -> HashMap<ServiceKey, Vec<EndpointValue>> {
    let service_ips = service_ips_from_service(service);
    let spec = coalesce_mesh_endpoints(&ctx.mesh_endpoint_state, service);
    let mesh_endpoint = MeshEndpoint::new("dummy", spec);
    mesh_endpoint.generate_bpf_service_endpoints(&service_ips)
}

fn reconcile_nodeport<B: ServiceBpfState>(
    service: &Service,
    ctx: &Context<B>,
    desired_services: &HashMap<ServiceKey, Vec<EndpointValue>>,
    local_nodeport_services: &HashMap<ServiceKey, Vec<EndpointValue>>,
    external_traffic_policy: ExternalTrafficPolicy,
    is_deletion: bool,
) -> Result<()> {
    let desired = generate_desired_nodeport(
        service,
        desired_services,
        local_nodeport_services,
        external_traffic_policy,
    );
    let desired_frontends = desired
        .iter()
        .map(|(frontend, value)| (*frontend, value.service_key))
        .collect::<HashMap<_, _>>();
    let current = ctx.service_bpf_state.nodeport_state()?;
    let (keys_to_remove, entries_to_upsert) =
        diff_nodeport_reconcile_actions(service, &current, &desired_frontends, is_deletion);

    for key in keys_to_remove {
        ctx.service_bpf_state.remove_nodeport_policy(&key)?;
        ctx.service_bpf_state.remove_nodeport(&key)?;
    }

    for (key, service_key) in entries_to_upsert {
        let Some(desired_value) = desired.get(&key) else {
            continue;
        };
        ctx.service_bpf_state
            .update_nodeport_policy(key, desired_value.policy)?;
        ctx.service_bpf_state.update_nodeport(key, service_key)?;
    }

    Ok(())
}

#[derive(Clone, Copy)]
struct DesiredNodePort {
    service_key: ServiceKey,
    policy: NodePortFrontendValue,
}

type NodePortKeyFamilyFn = fn(NodePortKey) -> NodePortMapKey;

fn node_port_key_family(service_key: &ServiceKey) -> (u16, u8, NodePortKeyFamilyFn) {
    match service_key {
        ServiceKey::V4(v4) => (v4.port, v4.protocol, NodePortMapKey::V4),
        ServiceKey::V6(v6) => (v6.port, v6.protocol, NodePortMapKey::V6),
    }
}

fn generate_desired_nodeport(
    service: &Service,
    desired_services: &HashMap<ServiceKey, Vec<EndpointValue>>,
    local_nodeport_services: &HashMap<ServiceKey, Vec<EndpointValue>>,
    external_traffic_policy: ExternalTrafficPolicy,
) -> HashMap<NodePortMapKey, DesiredNodePort> {
    if external_traffic_policy == ExternalTrafficPolicy::Local {
        return local_nodeport_services
            .keys()
            .map(|service_key| {
                let (node_port, protocol, family) = node_port_key_family(service_key);
                (
                    family(NodePortKey::new(node_port, protocol)),
                    DesiredNodePort {
                        service_key: *service_key,
                        policy: NodePortFrontendValue::with_snat(false),
                    },
                )
            })
            .collect();
    }

    let mut desired = HashMap::default();
    let service_port_to_node_port = node_port_targets(service);
    let local_by_frontend = local_nodeport_services
        .keys()
        .map(|service_key| {
            let (node_port, protocol, family) = node_port_key_family(service_key);
            (family(NodePortKey::new(node_port, protocol)), *service_key)
        })
        .collect::<HashMap<_, _>>();

    for service_key in desired_services.keys() {
        let (service_port, protocol, family) = node_port_key_family(service_key);

        let Some(node_port) = service_port_to_node_port.get(&(service_port, protocol)) else {
            continue;
        };
        let frontend_key = family(NodePortKey::new(*node_port, protocol));
        let (target_service_key, should_snat) =
            if let Some(local_key) = local_by_frontend.get(&frontend_key) {
                (*local_key, false)
            } else {
                (*service_key, true)
            };

        desired.insert(
            frontend_key,
            DesiredNodePort {
                service_key: target_service_key,
                policy: NodePortFrontendValue::with_snat(should_snat),
            },
        );
    }

    desired
}

fn external_traffic_policy(service: &Service) -> ExternalTrafficPolicy {
    let Some(spec) = service.spec.as_ref() else {
        return ExternalTrafficPolicy::Cluster;
    };
    match spec.external_traffic_policy.as_deref() {
        Some("Local") => ExternalTrafficPolicy::Local,
        _ => ExternalTrafficPolicy::Cluster,
    }
}

fn filter_colliding_local_nodeport_services(
    service: &Service,
    desired_services: &HashMap<ServiceKey, Vec<EndpointValue>>,
    local_nodeport_services: HashMap<ServiceKey, Vec<EndpointValue>>,
) -> HashMap<ServiceKey, Vec<EndpointValue>> {
    local_nodeport_services
        .into_iter()
        .filter_map(|(service_key, endpoints)| {
            if desired_services.contains_key(&service_key) {
                warn!(
                    service = %service.name_any(),
                    namespace = service.namespace().unwrap_or_default(),
                    ?service_key,
                    "skipping Local nodeport-specific service key due to collision with base service key"
                );
                None
            } else {
                Some((service_key, endpoints))
            }
        })
        .collect()
}

fn generate_local_nodeport_service_pairs<B: ServiceBpfState>(
    service: &Service,
    ctx: &Context<B>,
) -> HashMap<ServiceKey, Vec<EndpointValue>> {
    let mut result: HashMap<ServiceKey, Vec<EndpointValue>> = HashMap::default();
    let service_ips = service_ips_from_service(service);
    let targets = nodeport_targets_with_name(service);
    if targets.is_empty() {
        return result;
    }
    let slices = service_owned_endpoint_slices(service, ctx);
    for slice in slices {
        let slice = slice.as_ref();
        let local_backend_ips = local_backend_ips_from_ep_slice(slice, &ctx.node_name);
        if local_backend_ips.is_empty() {
            continue;
        }
        for target in &targets {
            let Some(backend_port) =
                backend_port_from_ep_slice(slice, &target.name, target.protocol)
            else {
                continue;
            };

            for service_ip in &service_ips {
                for backend_ip in &local_backend_ips {
                    let endpoint = match (service_ip, backend_ip) {
                        (IpAddr::V4(svc_v4), IpAddr::V4(ep_v4)) => {
                            let key = ServiceKey::v4(
                                svc_v4.to_bits(),
                                target.node_port,
                                target.protocol as u8,
                            );
                            let value =
                                EndpointValue::V4(mesh_cni_ebpf_common::service::EndpointValueV4 {
                                    ip: ep_v4.to_bits(),
                                    port: backend_port,
                                    _protocol: target.protocol as u8,
                                });
                            (key, value)
                        }
                        (IpAddr::V6(svc_v6), IpAddr::V6(ep_v6)) => {
                            let key = ServiceKey::v6(
                                svc_v6.to_bits(),
                                target.node_port,
                                target.protocol as u8,
                            );
                            let value =
                                EndpointValue::V6(mesh_cni_ebpf_common::service::EndpointValueV6 {
                                    ip: ep_v6.to_bits(),
                                    port: backend_port,
                                    _protocol: target.protocol as u8,
                                });
                            (key, value)
                        }
                        _ => continue,
                    };
                    result.entry(endpoint.0).or_default().push(endpoint.1);
                }
            }
        }
    }
    result
}

struct NodePortTarget {
    name: String,
    node_port: u16,
    protocol: KubeProtocol,
}

fn nodeport_targets_with_name(service: &Service) -> Vec<NodePortTarget> {
    let mut targets = Vec::new();
    let Some(spec) = service.spec.as_ref() else {
        return targets;
    };
    let Some(ports) = spec.ports.as_ref() else {
        return targets;
    };
    for port in ports {
        let Some(node_port) = port.node_port else {
            continue;
        };
        let Ok(node_port) = u16::try_from(node_port) else {
            continue;
        };
        let protocol = match port.protocol.as_deref() {
            Some(p) => KubeProtocol::try_from(p).unwrap_or_default(),
            None => KubeProtocol::default(),
        };
        targets.push(NodePortTarget {
            name: port.name.clone().unwrap_or_default(),
            node_port,
            protocol,
        });
    }
    targets
}

fn service_owned_endpoint_slices<B: ServiceBpfState>(
    service: &Service,
    ctx: &Context<B>,
) -> Vec<Arc<EndpointSlice>> {
    let Some(namespace) = service.namespace() else {
        return Vec::new();
    };
    let service_name = service.name_any();
    ctx.endpoint_slice_state
        .state()
        .iter()
        .filter(|slice| {
            slice.namespace().as_deref() == Some(namespace.as_str())
                && slice.labels().get(SERVICE_OWNER_LABEL) == Some(&service_name)
        })
        .cloned()
        .collect()
}

fn endpoint_ready(ep_cond: &EndpointConditions) -> bool {
    (ep_cond.ready == Some(true) || ep_cond.ready.is_none()) && (ep_cond.terminating != Some(true))
}

fn local_backend_ips_from_ep_slice(slice: &EndpointSlice, node_name: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for endpoint in &slice.endpoints {
        if endpoint.node_name.as_deref() != Some(node_name) {
            continue;
        }
        let endpoint_is_ready = endpoint
            .conditions
            .as_ref()
            .map(endpoint_ready)
            .unwrap_or(true);
        if !endpoint_is_ready {
            continue;
        }
        for ip in &endpoint.addresses {
            let Ok(ip) = ip.parse() else {
                continue;
            };
            ips.push(ip);
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
        let name_matches = (name.is_empty() && p.name.is_none()) || p.name.as_deref() == Some(name);
        if name_matches
            && let Some(port) = p.port
            && match p.protocol.as_deref() {
                Some(proto) => KubeProtocol::try_from(proto).unwrap_or_default() == protocol,
                None => KubeProtocol::default() == protocol,
            }
        {
            return u16::try_from(port).ok();
        }
    }
    None
}

fn node_port_targets(service: &Service) -> HashMap<(u16, u8), u16> {
    let mut map = HashMap::default();
    let Some(spec) = service.spec.as_ref() else {
        return map;
    };
    let Some(ports) = spec.ports.as_ref() else {
        return map;
    };

    for port in ports {
        let Some(node_port) = port.node_port else {
            continue;
        };
        let Ok(service_port) = u16::try_from(port.port) else {
            continue;
        };
        let Ok(node_port) = u16::try_from(node_port) else {
            continue;
        };
        let protocol = match port.protocol.as_deref() {
            Some(p) => KubeProtocol::try_from(p).unwrap_or_default(),
            None => KubeProtocol::default(),
        } as u8;
        map.insert((service_port, protocol), node_port);
    }
    map
}

fn nodeport_owned_keys(
    service: &Service,
    current_state: &HashMap<NodePortMapKey, ServiceKey>,
) -> HashSet<NodePortMapKey> {
    let ips = service_ip_sets(service);
    current_state
        .iter()
        .filter_map(|(frontend_key, service_key)| {
            if key_matches_service_ip(service_key, &ips) {
                Some(*frontend_key)
            } else {
                None
            }
        })
        .collect()
}

fn diff_nodeport_reconcile_actions(
    service: &Service,
    current_state: &HashMap<NodePortMapKey, ServiceKey>,
    desired_state: &HashMap<NodePortMapKey, ServiceKey>,
    is_deletion: bool,
) -> (HashSet<NodePortMapKey>, Vec<(NodePortMapKey, ServiceKey)>) {
    let owned_keys = nodeport_owned_keys(service, current_state);
    if is_deletion {
        let mut keys_to_remove = owned_keys;
        keys_to_remove.extend(desired_state.keys().copied());
        return (keys_to_remove, Vec::new());
    }

    let keys_to_remove = owned_keys
        .into_iter()
        .filter(|key| !desired_state.contains_key(key))
        .collect();
    let entries_to_upsert = desired_state.iter().map(|(k, v)| (*k, *v)).collect();
    (keys_to_remove, entries_to_upsert)
}

fn service_owned_keys(
    service: &Service,
    current_state: &HashMap<ServiceKey, Vec<EndpointValue>>,
) -> HashSet<ServiceKey> {
    let ips = service_ip_sets(service);
    current_state
        .keys()
        .copied()
        .filter(|key| key_matches_service_ip(key, &ips))
        .collect()
}

fn service_ip_sets(service: &Service) -> HashSet<IpAddr> {
    let mut ips = HashSet::default();
    if let Some(spec) = &service.spec
        && let Some(cluster_ips) = &spec.cluster_ips
    {
        for cluster_ip in cluster_ips {
            let Ok(cluster_ip) = cluster_ip.parse::<IpAddr>() else {
                continue;
            };
            ips.insert(cluster_ip);
        }
    }
    ips
}

fn key_matches_service_ip(key: &ServiceKey, ips: &HashSet<IpAddr>) -> bool {
    let service_ip = match key {
        ServiceKey::V4(key) => IpAddr::V4(Ipv4Addr::from_bits(key.ip)),
        ServiceKey::V6(key) => IpAddr::V6(Ipv6Addr::from_bits(key.ip)),
    };
    ips.contains(&service_ip)
}

fn mesh_endpoint_count_for_service<B: ServiceBpfState>(
    service: &Service,
    ctx: &Context<B>,
) -> usize {
    let Some(namespace) = service.namespace() else {
        return 0;
    };
    let service_name = service.name_any();
    ctx.mesh_endpoint_state
        .state()
        .iter()
        .filter(|mesh_endpoint| {
            mesh_endpoint.namespace().as_deref() == Some(namespace.as_str())
                && mesh_endpoint.labels().get(SERVICE_OWNER_LABEL) == Some(&service_name)
        })
        .count()
}

fn should_preserve_current_backends(
    is_deletion: bool,
    desired_is_empty: bool,
    mesh_endpoint_count: usize,
    service_owned_key_count: usize,
) -> bool {
    !is_deletion && desired_is_empty && mesh_endpoint_count == 0 && service_owned_key_count > 0
}

fn diff_service_reconcile_actions(
    service: &Service,
    current_state: &HashMap<ServiceKey, Vec<EndpointValue>>,
    desired_state: &HashMap<ServiceKey, Vec<EndpointValue>>,
    is_deletion: bool,
) -> (HashSet<ServiceKey>, Vec<(ServiceKey, Vec<EndpointValue>)>) {
    let service_owned_keys = service_owned_keys(service, current_state);
    if is_deletion {
        let mut keys_to_remove = service_owned_keys;
        keys_to_remove.extend(desired_state.keys().copied());
        return (keys_to_remove, Vec::new());
    }

    let keys_to_remove = service_owned_keys
        .into_iter()
        .filter(|key| !desired_state.contains_key(key))
        .collect();

    let entries_to_upsert = desired_state
        .iter()
        .map(|(key, endpoints)| (*key, endpoints.clone()))
        .collect();

    (keys_to_remove, entries_to_upsert)
}

fn is_meshed_service(service: &Service) -> bool {
    let val = service
        .annotations()
        .get(ANNOTATION_MESH_SERVICE)
        .or_else(|| service.labels().get(ANNOTATION_MESH_SERVICE));
    let Some(val) = val else {
        return false;
    };
    val.to_lowercase() == "true"
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use ahash::{HashMap, HashSet};
    use k8s_openapi::api::core::v1::{Service, ServiceSpec};
    use mesh_cni_ebpf_common::{
        KubeProtocol,
        service::{EndpointValue, EndpointValueV4, EndpointValueV6, NodePortKey, ServiceKey},
    };

    use crate::NodePortMapKey;

    use super::{
        diff_nodeport_reconcile_actions, diff_service_reconcile_actions,
        should_preserve_current_backends,
    };

    fn service_with_cluster_ips(ips: &[&str]) -> Service {
        Service {
            metadata: kube::core::ObjectMeta {
                namespace: Some("default".to_string()),
                name: Some("svc".to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ips: Some(ips.iter().map(|ip| (*ip).to_string()).collect()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn key(ip: IpAddr, port: u16) -> ServiceKey {
        match ip {
            IpAddr::V4(ip) => ServiceKey::v4(ip.to_bits(), port, KubeProtocol::Tcp as u8),
            IpAddr::V6(ip) => ServiceKey::v6(ip.to_bits(), port, KubeProtocol::Tcp as u8),
        }
    }

    fn endpoint_values(ip: IpAddr, port: u16) -> Vec<EndpointValue> {
        let ep = match ip {
            IpAddr::V4(ip) => EndpointValue::V4(EndpointValueV4 {
                ip: ip.to_bits(),
                port,
                _protocol: KubeProtocol::Tcp as u8,
            }),
            IpAddr::V6(ip) => EndpointValue::V6(EndpointValueV6 {
                ip: ip.to_bits(),
                port,
                _protocol: KubeProtocol::Tcp as u8,
            }),
        };
        vec![ep]
    }

    fn nodeport_v4(port: u16, protocol: KubeProtocol) -> NodePortMapKey {
        NodePortMapKey::V4(NodePortKey::new(port, protocol as u8))
    }

    #[test]
    fn diff_non_deletion_removes_only_stale_owned_keys() {
        let service = service_with_cluster_ips(&["10.96.0.10"]);
        let stale_owned = key(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10)), 80);
        let desired_owned = key(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10)), 443);
        let foreign = key(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 55)), 80);

        let mut current = HashMap::default();
        current.insert(
            stale_owned,
            endpoint_values(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080),
        );
        current.insert(
            desired_owned,
            endpoint_values(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8443),
        );
        current.insert(
            foreign,
            endpoint_values(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 8080),
        );

        let mut desired = HashMap::default();
        desired.insert(
            desired_owned,
            endpoint_values(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8443),
        );

        let (removes, upserts) =
            diff_service_reconcile_actions(&service, &current, &desired, false);

        let expected_removes: HashSet<_> = [stale_owned].into_iter().collect();
        assert_eq!(removes, expected_removes);
        assert_eq!(upserts.len(), 1);
        assert_eq!(upserts[0].0, desired_owned);
        assert_eq!(
            upserts[0].1,
            endpoint_values(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8443)
        );
    }

    #[test]
    fn diff_deletion_removes_union_of_owned_and_desired_keys() {
        let service = service_with_cluster_ips(&["10.96.0.10"]);
        let owned_in_current = key(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10)), 80);
        let desired_only = key(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10)), 443);
        let foreign = key(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 99)), 80);

        let mut current = HashMap::default();
        current.insert(
            owned_in_current,
            endpoint_values(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080),
        );
        current.insert(
            foreign,
            endpoint_values(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 8080),
        );

        let mut desired = HashMap::default();
        desired.insert(
            desired_only,
            endpoint_values(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8443),
        );

        let (removes, upserts) = diff_service_reconcile_actions(&service, &current, &desired, true);

        let expected_removes: HashSet<_> = [owned_in_current, desired_only].into_iter().collect();
        assert_eq!(removes, expected_removes);
        assert!(upserts.is_empty());
    }

    #[test]
    fn diff_handles_mixed_v4_v6_service_keys() {
        let service = service_with_cluster_ips(&["10.96.0.10", "fd00::10"]);
        let owned_v4 = key(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10)), 80);
        let owned_v6 = key(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0010)),
            80,
        );
        let foreign_v6 = key(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0020)),
            80,
        );

        let mut current = HashMap::default();
        current.insert(
            owned_v4,
            endpoint_values(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080),
        );
        current.insert(
            owned_v6,
            endpoint_values(
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x1010)),
                8080,
            ),
        );
        current.insert(
            foreign_v6,
            endpoint_values(
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x2020)),
                8080,
            ),
        );

        let desired = HashMap::default();
        let (removes, upserts) =
            diff_service_reconcile_actions(&service, &current, &desired, false);

        let expected_removes: HashSet<_> = [owned_v4, owned_v6].into_iter().collect();
        assert_eq!(removes, expected_removes);
        assert!(upserts.is_empty());
    }

    #[test]
    fn preserve_current_backends_when_meshendpoints_absent() {
        assert!(should_preserve_current_backends(false, true, 0, 1));
    }

    #[test]
    fn no_preserve_when_service_is_deleting() {
        assert!(!should_preserve_current_backends(true, true, 0, 1));
    }

    #[test]
    fn no_preserve_when_meshendpoints_exist() {
        assert!(!should_preserve_current_backends(false, true, 1, 1));
    }

    #[test]
    fn no_preserve_when_no_owned_backends_exist() {
        assert!(!should_preserve_current_backends(false, true, 0, 0));
    }

    #[test]
    fn nodeport_diff_non_deletion_removes_stale_owned_frontend_keys() {
        let service = service_with_cluster_ips(&["10.96.0.10"]);
        let stale = nodeport_v4(30080, KubeProtocol::Tcp);
        let desired_key = nodeport_v4(30443, KubeProtocol::Tcp);
        let foreign = nodeport_v4(30999, KubeProtocol::Tcp);

        let mut current = HashMap::default();
        current.insert(stale, key(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10)), 80));
        current.insert(
            desired_key,
            key(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10)), 443),
        );
        current.insert(foreign, key(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 99)), 80));

        let mut desired = HashMap::default();
        desired.insert(
            desired_key,
            key(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10)), 443),
        );

        let (removes, upserts) =
            diff_nodeport_reconcile_actions(&service, &current, &desired, false);

        let expected_removes: HashSet<_> = [stale].into_iter().collect();
        assert_eq!(removes, expected_removes);
        let upserts: HashSet<_> = upserts.into_iter().collect();
        let expected_upserts: HashSet<_> = [(
            desired_key,
            *desired.get(&desired_key).expect("desired key"),
        )]
        .into_iter()
        .collect();
        assert_eq!(upserts, expected_upserts);
    }

    #[test]
    fn nodeport_diff_deletion_removes_owned_and_desired_keys() {
        let service = service_with_cluster_ips(&["10.96.0.10"]);
        let owned = nodeport_v4(30080, KubeProtocol::Tcp);
        let desired_only = nodeport_v4(30443, KubeProtocol::Tcp);
        let foreign = nodeport_v4(30999, KubeProtocol::Tcp);

        let mut current = HashMap::default();
        current.insert(owned, key(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10)), 80));
        current.insert(foreign, key(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 99)), 80));

        let mut desired = HashMap::default();
        desired.insert(
            desired_only,
            key(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10)), 443),
        );

        let (removes, upserts) =
            diff_nodeport_reconcile_actions(&service, &current, &desired, true);

        let expected_removes: HashSet<_> = [owned, desired_only].into_iter().collect();
        assert_eq!(removes, expected_removes);
        assert!(upserts.is_empty());
    }
}
