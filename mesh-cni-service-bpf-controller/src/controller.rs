use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use ahash::{HashMap, HashSet};
use k8s_openapi::api::core::v1::{Service, ServiceSpec};
use kube::{Resource, ResourceExt, runtime::controller::Action};
use mesh_cni_crds::v1alpha1::meshendpoint::{
    MeshEndpoint, coalesce_mesh_endpoints, generate_mesh_endpoint_spec, service_ips_from_service,
};
use mesh_cni_ebpf_common::{
    KubeProtocol,
    service::{EndpointValue, NodePortKey, ServiceKey},
};
use mesh_cni_meshendpoint_gen_controller::ANNOTATION_MESH_SERVICE;
use tracing::{error, info};

use crate::{Context, Error, NodePortReader, NodePortWriter, Result, ServiceReader, ServiceWriter};

const DEFAULT_REQUEUE_DURATION: Duration = Duration::from_secs(300);
const ERROR_REQUEUE_DURATION: Duration = Duration::from_secs(5);
const MISSING_MESH_ENDPOINT_REQUEUE_DURATION: Duration = Duration::from_secs(5);
pub const SERVICE_OWNER_LABEL: &str = "kubernetes.io/service-name";

pub async fn reconcile<B: ServiceWriter + ServiceReader>(
    service: Arc<Service>,
    ctx: Arc<Context<B>>,
) -> Result<Action> {
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

pub async fn reconcile_nodeports<B: NodePortWriter + NodePortReader>(
    service: Arc<Service>,
    ctx: Arc<Context<B>>,
) -> Result<Action> {
    let ns = service
        .namespace()
        .ok_or_else(|| Error::ReconcileMissingPrecondition("missing namespace".into()))?;
    let ns_name = format!("{}/{}", ns, service.name_any());
    info!("started reconciling NodePort state for Service {}", ns_name);

    inner_reconcile_nodeports(&service, &ctx)?;
    Ok(Action::await_change())
}

pub(crate) fn reconcile_all_nodeports<B: NodePortWriter + NodePortReader>(
    ctx: &Context<B>,
) -> Result<()> {
    let desired_nodeports = desired_nodeport_mappings_for_services(&ctx.service_state.state());
    let current_nodeports = ctx.service_bpf_state.nodeport_state()?;
    let (keys_to_remove, keys_to_upsert) =
        diff_global_nodeport_reconcile_actions(&current_nodeports, &desired_nodeports);

    for key in keys_to_remove {
        ctx.service_bpf_state.remove_nodeport(&key)?;
    }
    for (nodeport_key, service_key) in keys_to_upsert {
        ctx.service_bpf_state
            .upsert_nodeport(nodeport_key, service_key)?;
    }

    Ok(())
}

pub async fn reconcile_local_service<B: ServiceWriter + ServiceReader>(
    service: Arc<Service>,
    ctx: Arc<Context<B>>,
) -> Result<Action> {
    let desired = generate_desired_service_pairs(&service, &ctx);
    let current = ctx.service_bpf_state.service_state()?;
    let is_deletion = service.meta().deletion_timestamp.is_some();
    let (keys_to_remove, entries_to_upsert) =
        diff_service_reconcile_actions(&service, &current, &desired, is_deletion);

    for key in keys_to_remove {
        ctx.service_bpf_state.remove_service(&key)?;
    }

    for (key, endpoints) in entries_to_upsert {
        ctx.service_bpf_state.upsert_service(key, endpoints)?;
    }

    Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
}

pub async fn reconcile_multi_cluster_service<B: ServiceWriter + ServiceReader>(
    service: Arc<Service>,
    ctx: Arc<Context<B>>,
) -> Result<Action> {
    let desired = generate_service_pairs_from_meps(&service, &ctx);
    let current = ctx.service_bpf_state.service_state()?;
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

    let (keys_to_remove, entries_to_upsert) =
        diff_service_reconcile_actions(&service, &current, &desired, is_deletion);

    for key in keys_to_remove {
        ctx.service_bpf_state.remove_service(&key)?;
    }

    for (key, endpoints) in entries_to_upsert {
        ctx.service_bpf_state.upsert_service(key, endpoints)?;
    }

    Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
}

pub fn error_policy<B>(service: Arc<Service>, err: &Error, _ctx: Arc<Context<B>>) -> Action {
    let ns = service.namespace().unwrap_or_default();
    let ns_name = format!("{}/{}", ns, service.name_any());
    error!(%err, "error reconciling {}", ns_name);
    Action::requeue(ERROR_REQUEUE_DURATION)
}

fn generate_desired_service_pairs<B>(
    service: &Service,
    ctx: &Context<B>,
) -> HashMap<ServiceKey, Vec<EndpointValue>> {
    let service_ips = service_ips_from_service(service);
    let spec = generate_mesh_endpoint_spec(&ctx.endpoint_slice_state, service);
    let mesh_endpoint = MeshEndpoint::new("dummy", spec);
    mesh_endpoint.generate_bpf_service_endpoints(&service_ips)
}

fn generate_service_pairs_from_meps<B>(
    service: &Service,
    ctx: &Context<B>,
) -> HashMap<ServiceKey, Vec<EndpointValue>> {
    let service_ips = service_ips_from_service(service);
    let spec = coalesce_mesh_endpoints(&ctx.mesh_endpoint_state, service);
    let mesh_endpoint = MeshEndpoint::new("dummy", spec);
    mesh_endpoint.generate_bpf_service_endpoints(&service_ips)
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

fn mesh_endpoint_count_for_service<B>(service: &Service, ctx: &Context<B>) -> usize {
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

fn inner_reconcile_nodeports<B: NodePortWriter + NodePortReader>(
    service: &Service,
    ctx: &Context<B>,
) -> Result<()> {
    let nodeport_state = ctx.service_bpf_state.nodeport_state()?;
    let is_deletion = service.meta().deletion_timestamp.is_some();
    let desired = if !is_deletion && is_nodeport_service_type(service) {
        desired_nodeport_mappings(service)
    } else {
        HashMap::default()
    };
    let (keys_to_remove, entries_to_upsert) =
        diff_nodeport_reconcile_actions(service, &nodeport_state, &desired, is_deletion);

    for key in keys_to_remove {
        ctx.service_bpf_state.remove_nodeport(&key)?;
    }
    for (nodeport_key, service_key) in entries_to_upsert {
        ctx.service_bpf_state
            .upsert_nodeport(nodeport_key, service_key)?;
    }
    Ok(())
}

fn is_nodeport_service_type(service: &Service) -> bool {
    service
        .spec
        .as_ref()
        .and_then(|spec| spec.type_.as_deref())
        .is_some_and(|service_type| matches!(service_type, "LoadBalancer" | "NodePort"))
}

fn nodeport_owned_keys(
    service: &Service,
    current_state: &HashMap<NodePortKey, ServiceKey>,
) -> HashSet<NodePortKey> {
    let ips = service_ip_sets(service);
    current_state
        .iter()
        .filter_map(|(nodeport_key, service_key)| {
            if key_matches_service_ip(service_key, &ips) {
                Some(*nodeport_key)
            } else {
                None
            }
        })
        .collect()
}

fn diff_nodeport_reconcile_actions(
    service: &Service,
    current_state: &HashMap<NodePortKey, ServiceKey>,
    desired_state: &HashMap<NodePortKey, ServiceKey>,
    is_deletion: bool,
) -> (HashSet<NodePortKey>, Vec<(NodePortKey, ServiceKey)>) {
    let owned_nodeport_keys = nodeport_owned_keys(service, current_state);
    if is_deletion {
        return (owned_nodeport_keys, Vec::new());
    }

    let keys_to_remove = owned_nodeport_keys
        .into_iter()
        .filter(|nodeport_key| !desired_state.contains_key(nodeport_key))
        .collect();

    let entries_to_upsert = desired_state
        .iter()
        .map(|(nodeport_key, service_key)| (*nodeport_key, *service_key))
        .collect();

    (keys_to_remove, entries_to_upsert)
}

fn desired_nodeport_mappings_for_services(
    services: &[Arc<Service>],
) -> HashMap<NodePortKey, ServiceKey> {
    let mut desired = HashMap::default();
    for service in services {
        if service.meta().deletion_timestamp.is_some() || !is_nodeport_service_type(service) {
            continue;
        }
        for (nodeport_key, service_key) in desired_nodeport_mappings(service) {
            desired.insert(nodeport_key, service_key);
        }
    }
    desired
}

fn diff_global_nodeport_reconcile_actions(
    current_state: &HashMap<NodePortKey, ServiceKey>,
    desired_state: &HashMap<NodePortKey, ServiceKey>,
) -> (HashSet<NodePortKey>, Vec<(NodePortKey, ServiceKey)>) {
    let keys_to_remove = current_state
        .keys()
        .filter(|key| !desired_state.contains_key(*key))
        .copied()
        .collect();
    let keys_to_upsert = desired_state
        .iter()
        .map(|(nodeport_key, service_key)| (*nodeport_key, *service_key))
        .collect();
    (keys_to_remove, keys_to_upsert)
}

fn desired_nodeport_mappings(service: &Service) -> HashMap<NodePortKey, ServiceKey> {
    let mut desired = HashMap::default();
    let Some(cluster_ip) = first_ipv4_cluster_ip(service) else {
        return desired;
    };
    let Some(spec) = &service.spec else {
        return desired;
    };

    for (nodeport_key, service_port, protocol) in nodeport_ports(spec) {
        let service_key = ServiceKey::v4(cluster_ip.to_bits(), service_port, protocol as u8);
        desired.insert(nodeport_key, service_key);
    }

    desired
}

fn nodeport_ports(spec: &ServiceSpec) -> Vec<(NodePortKey, u16, KubeProtocol)> {
    let mut ports = Vec::new();
    let Some(service_ports) = &spec.ports else {
        return ports;
    };

    for port_spec in service_ports {
        let Some(node_port) = port_spec
            .node_port
            .and_then(|port| u16::try_from(port).ok())
        else {
            continue;
        };
        let Some(service_port) = u16::try_from(port_spec.port).ok() else {
            continue;
        };
        let protocol = match &port_spec.protocol {
            Some(protocol) => KubeProtocol::try_from(protocol.as_str()).unwrap_or_default(),
            None => KubeProtocol::Tcp,
        };
        ports.push((
            NodePortKey::new(node_port, protocol as u8),
            service_port,
            protocol,
        ));
    }
    ports
}

fn first_ipv4_cluster_ip(service: &Service) -> Option<Ipv4Addr> {
    let spec = service.spec.as_ref()?;
    let cluster_ips = spec.cluster_ips.as_ref()?;
    for cluster_ip in cluster_ips {
        let Ok(ip_addr) = cluster_ip.parse::<IpAddr>() else {
            continue;
        };
        if let IpAddr::V4(ip) = ip_addr {
            return Some(ip);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };

    use ahash::{HashMap, HashSet};
    use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
    use mesh_cni_ebpf_common::{
        KubeProtocol,
        service::{EndpointValue, EndpointValueV4, EndpointValueV6, NodePortKey, ServiceKey},
    };

    use super::{
        desired_nodeport_mappings, desired_nodeport_mappings_for_services,
        diff_global_nodeport_reconcile_actions, diff_nodeport_reconcile_actions,
        diff_service_reconcile_actions, should_preserve_current_backends,
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

    fn service_with_nodeports(cluster_ips: &[&str], ports: &[(u16, u16, &str)]) -> Service {
        let service_ports = ports
            .iter()
            .map(|(port, node_port, protocol)| ServicePort {
                port: i32::from(*port),
                node_port: Some(i32::from(*node_port)),
                protocol: Some((*protocol).to_string()),
                ..Default::default()
            })
            .collect();
        Service {
            metadata: kube::core::ObjectMeta {
                namespace: Some("default".to_string()),
                name: Some("svc".to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ips: Some(cluster_ips.iter().map(|ip| (*ip).to_string()).collect()),
                ports: Some(service_ports),
                type_: Some(String::from("NodePort")),
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
    fn desired_nodeport_mappings_uses_nodeport_key_and_v4_service_key() {
        let service = service_with_nodeports(&["10.96.0.10"], &[(80, 30080, "TCP")]);
        let service_key = ServiceKey::v4(
            Ipv4Addr::new(10, 96, 0, 10).to_bits(),
            80,
            KubeProtocol::Tcp as u8,
        );

        let desired = desired_nodeport_mappings(&service);
        let nodeport_key = NodePortKey::new(30080, KubeProtocol::Tcp as u8);
        assert_eq!(desired.get(&nodeport_key), Some(&service_key));
    }

    #[test]
    fn nodeport_global_diff_removes_keys_not_in_desired() {
        let desired_key = NodePortKey::new(30080, KubeProtocol::Tcp as u8);
        let stale_key = NodePortKey::new(30081, KubeProtocol::Tcp as u8);

        let mut current = HashMap::default();
        current.insert(
            desired_key,
            ServiceKey::v4(
                Ipv4Addr::new(10, 96, 0, 10).to_bits(),
                80,
                KubeProtocol::Tcp as u8,
            ),
        );
        current.insert(
            stale_key,
            ServiceKey::v4(
                Ipv4Addr::new(10, 96, 0, 11).to_bits(),
                80,
                KubeProtocol::Tcp as u8,
            ),
        );

        let mut desired = HashMap::default();
        desired.insert(
            desired_key,
            ServiceKey::v4(
                Ipv4Addr::new(10, 96, 0, 10).to_bits(),
                80,
                KubeProtocol::Tcp as u8,
            ),
        );
        let (to_remove, to_upsert) = diff_global_nodeport_reconcile_actions(&current, &desired);

        let expected_remove: HashSet<_> = [stale_key].into_iter().collect();
        assert_eq!(to_remove, expected_remove);
        assert_eq!(to_upsert.len(), 1);
        assert_eq!(to_upsert[0].0, desired_key);
    }

    #[test]
    fn desired_nodeport_mappings_for_services_skips_non_nodeport_service_types() {
        let nodeport_service = service_with_nodeports(&["10.96.0.10"], &[(80, 30080, "TCP")]);
        let mut cluster_ip_service = service_with_nodeports(&["10.96.0.20"], &[(80, 30090, "TCP")]);
        if let Some(spec) = &mut cluster_ip_service.spec {
            spec.type_ = Some("ClusterIP".to_string());
        }
        let services = vec![Arc::new(nodeport_service), Arc::new(cluster_ip_service)];

        let desired = desired_nodeport_mappings_for_services(&services);
        let nodeport_key = NodePortKey::new(30080, KubeProtocol::Tcp as u8);
        let cluster_ip_nodeport_key = NodePortKey::new(30090, KubeProtocol::Tcp as u8);

        assert!(desired.contains_key(&nodeport_key));
        assert!(!desired.contains_key(&cluster_ip_nodeport_key));
    }

    #[test]
    fn nodeport_diff_removes_stale_owned_keys_on_port_change() {
        let service = service_with_nodeports(&["10.96.0.10"], &[(80, 30081, "TCP")]);
        let stale_owned = NodePortKey::new(30080, KubeProtocol::Tcp as u8);
        let desired_owned = NodePortKey::new(30081, KubeProtocol::Tcp as u8);
        let foreign = NodePortKey::new(30090, KubeProtocol::Tcp as u8);

        let mut current = HashMap::default();
        current.insert(
            stale_owned,
            ServiceKey::v4(
                Ipv4Addr::new(10, 96, 0, 10).to_bits(),
                80,
                KubeProtocol::Tcp as u8,
            ),
        );
        current.insert(
            foreign,
            ServiceKey::v4(
                Ipv4Addr::new(10, 96, 0, 20).to_bits(),
                80,
                KubeProtocol::Tcp as u8,
            ),
        );

        let desired = desired_nodeport_mappings(&service);
        let (to_remove, to_upsert) =
            diff_nodeport_reconcile_actions(&service, &current, &desired, false);

        let expected_remove: HashSet<_> = [stale_owned].into_iter().collect();
        assert_eq!(to_remove, expected_remove);
        assert_eq!(to_upsert.len(), 1);
        assert_eq!(to_upsert[0].0, desired_owned);
    }

    #[test]
    fn nodeport_diff_deletion_removes_all_owned_keys() {
        let service = service_with_nodeports(&["10.96.0.10"], &[(80, 30080, "TCP")]);
        let key_one = NodePortKey::new(30080, KubeProtocol::Tcp as u8);
        let key_two = NodePortKey::new(30081, KubeProtocol::Tcp as u8);
        let foreign = NodePortKey::new(30090, KubeProtocol::Tcp as u8);

        let mut current = HashMap::default();
        current.insert(
            key_one,
            ServiceKey::v4(
                Ipv4Addr::new(10, 96, 0, 10).to_bits(),
                80,
                KubeProtocol::Tcp as u8,
            ),
        );
        current.insert(
            key_two,
            ServiceKey::v4(
                Ipv4Addr::new(10, 96, 0, 10).to_bits(),
                443,
                KubeProtocol::Tcp as u8,
            ),
        );
        current.insert(
            foreign,
            ServiceKey::v4(
                Ipv4Addr::new(10, 96, 0, 20).to_bits(),
                80,
                KubeProtocol::Tcp as u8,
            ),
        );

        let desired = HashMap::default();
        let (to_remove, to_upsert) =
            diff_nodeport_reconcile_actions(&service, &current, &desired, true);

        let expected_remove: HashSet<_> = [key_one, key_two].into_iter().collect();
        assert_eq!(to_remove, expected_remove);
        assert!(to_upsert.is_empty());
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
}
