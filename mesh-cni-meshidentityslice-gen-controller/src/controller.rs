use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    hash::{Hash, Hasher},
    net::IpAddr,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use k8s_openapi::api::core::v1::{Namespace, Pod};
use kube::{
    Api, ResourceExt,
    api::{DeleteParams, Patch, PatchParams},
    runtime::{
        controller::Action,
        reflector::{ObjectRef, Store},
    },
};
use mesh_cni_crds::v1alpha1::meshidentityslice::{
    MeshIdentityEndpoint, MeshIdentityNamedPort, MeshIdentitySlice, MeshIdentitySliceSpec,
};
use mesh_cni_k8s_utils::sanitize_pod_labels;
use tracing::{error, info};

use crate::{Error, Result, context::Context};

const DEFAULT_REQUEUE_DURATION: Duration = Duration::from_secs(300);
const ERROR_REQUEUE_DURATION: Duration = Duration::from_secs(5);
const MANAGER: &str = "meshidentityslice-gen-controller";
pub(crate) const LABEL_CLUSTER_OWNER: &str = "mesh-cni.dev/cluster-owner";

pub async fn reconcile(namespace: Arc<Namespace>, ctx: Arc<Context>) -> Result<Action> {
    let namespace_name = namespace.name_any();
    info!(
        namespace = %namespace_name,
        cluster = %ctx.cluster_name,
        "started reconciling MeshIdentitySlice namespace set"
    );
    if ctx
        .local_namespaces
        .get(&ObjectRef::new(&namespace_name))
        .is_none()
    {
        info!(
            namespace = %namespace_name,
            "namespace does not exist in local cluster, skipping MeshIdentitySlice reconciliation"
        );
        return Ok(Action::await_change());
    }

    let api: Api<MeshIdentitySlice> = Api::namespaced(ctx.client.clone(), &namespace_name);

    let existing: Vec<Arc<MeshIdentitySlice>> = ctx
        .meshidentityslices
        .state()
        .into_iter()
        .filter(|slice| {
            slice.namespace().as_deref() == Some(namespace_name.as_str())
                && slice.labels().get(LABEL_CLUSTER_OWNER) == Some(&ctx.cluster_name)
        })
        .collect();

    if namespace.metadata.deletion_timestamp.is_some() {
        for slice in &existing {
            api.delete(&slice.name_any(), &DeleteParams::default())
                .await?;
        }
        return Ok(Action::await_change());
    }

    let desired = desired_slices_for_namespace(&namespace, &ctx.pods, &ctx.cluster_name);
    let desired_names: HashSet<String> = desired.iter().map(|s| s.name_any()).collect();
    let params = PatchParams::apply(MANAGER).force();

    for slice in desired {
        let name = slice.name_any();
        api.patch(&name, &params, &Patch::Apply(slice)).await?;
    }

    for slice in &existing {
        let name = slice.name_any();
        if !desired_names.contains(&name) {
            api.delete(&name, &DeleteParams::default()).await?;
        }
    }

    Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
}

pub fn error_policy(namespace: Arc<Namespace>, error: &Error, _ctx: Arc<Context>) -> Action {
    error!(
        namespace = %namespace.name_any(),
        %error,
        "failed to reconcile MeshIdentitySlice"
    );
    Action::requeue(ERROR_REQUEUE_DURATION)
}

fn desired_slices_for_namespace(
    namespace: &Namespace,
    pods: &Store<Pod>,
    cluster_name: &str,
) -> Vec<MeshIdentitySlice> {
    let namespace_name = namespace.name_any();
    let namespace_labels = namespace.labels().clone();

    let mut grouped: HashMap<
        BTreeMap<String, String>,
        BTreeMap<IpAddr, BTreeSet<MeshIdentityNamedPort>>,
    > = HashMap::default();

    for pod in pods.state() {
        if pod.namespace().as_deref() != Some(namespace_name.as_str()) {
            continue;
        }
        if pod.metadata.deletion_timestamp.is_some() {
            continue;
        }
        if pod
            .spec
            .as_ref()
            .is_some_and(|spec| spec.host_network == Some(true))
        {
            continue;
        }

        let mut labels = pod.labels().clone();
        sanitize_pod_labels(&mut labels);
        let ips = pod_ips(&pod);
        if ips.is_empty() {
            continue;
        }
        let named_ports = pod_named_ports(&pod);

        let endpoints = grouped.entry(labels).or_default();
        for ip in ips {
            endpoints
                .entry(ip)
                .or_default()
                .extend(named_ports.iter().cloned());
        }
    }

    let mut desired = Vec::with_capacity(grouped.len());
    for (pod_labels, endpoints_by_ip) in grouped {
        let name = mesh_identity_slice_name(cluster_name, &pod_labels);
        let spec = MeshIdentitySliceSpec {
            cluster: cluster_name.to_string(),
            pod_labels,
            namespace_labels: namespace_labels.clone(),
            endpoints: endpoints_by_ip
                .into_iter()
                .map(|(ip, named_ports)| MeshIdentityEndpoint {
                    ip,
                    named_ports: named_ports.into_iter().collect(),
                })
                .collect(),
        };
        let mut slice = MeshIdentitySlice::new(&name, spec);
        let labels = slice.labels_mut();
        labels.insert(LABEL_CLUSTER_OWNER.to_string(), cluster_name.to_string());
        desired.push(slice);
    }
    desired
}

fn mesh_identity_slice_name(cluster_name: &str, pod_labels: &BTreeMap<String, String>) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    cluster_name.hash(&mut hasher);
    pod_labels.hash(&mut hasher);
    let digest = hasher.finish();
    format!("{}-{:016x}", cluster_name, digest)
}

fn pod_ips(pod: &Pod) -> Vec<IpAddr> {
    let Some(status) = pod.status.as_ref() else {
        return Vec::new();
    };

    if let Some(ips) = status.pod_ips.as_ref() {
        return ips
            .iter()
            .filter_map(|ip| IpAddr::from_str(&ip.ip).ok())
            .collect();
    }

    status
        .pod_ip
        .as_deref()
        .and_then(|ip| IpAddr::from_str(ip).ok())
        .into_iter()
        .collect()
}

fn pod_named_ports(pod: &Pod) -> BTreeSet<MeshIdentityNamedPort> {
    let Some(spec) = pod.spec.as_ref() else {
        return BTreeSet::new();
    };

    let mut named_ports = BTreeSet::new();
    for container in &spec.containers {
        let Some(ports) = container.ports.as_ref() else {
            continue;
        };
        for container_port in ports {
            let Some(name) = container_port.name.as_ref() else {
                continue;
            };
            let Ok(port) = u16::try_from(container_port.container_port) else {
                continue;
            };
            let protocol = match container_port.protocol.as_deref() {
                None | Some("TCP") => "TCP",
                Some("UDP") => "UDP",
                Some("SCTP") => "SCTP",
                Some(_) => continue,
            };
            named_ports.insert(MeshIdentityNamedPort {
                name: name.clone(),
                protocol: protocol.to_string(),
                port,
            });
        }
    }
    named_ports
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet, HashMap},
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
    };

    use k8s_openapi::api::core::v1::{Namespace, PodIP, PodSpec, PodStatus};
    use kube::{
        ResourceExt,
        api::ObjectMeta,
        runtime::{reflector::store, watcher},
    };

    use super::*;

    fn make_pod_store(pods: Vec<Pod>) -> Store<Pod> {
        let (pod_store, mut pod_writer) = store();
        for pod in pods {
            pod_writer.apply_watcher_event(&watcher::Event::Apply(pod));
        }
        pod_store
    }

    fn make_namespace(name: &str, labels: HashMap<String, String>) -> Namespace {
        Namespace {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                labels: Some(labels.into_iter().collect()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn make_pod(
        name: &str,
        namespace: &str,
        labels: HashMap<String, String>,
        pod_ips: Vec<IpAddr>,
        host_network: bool,
    ) -> Pod {
        let status = if pod_ips.is_empty() {
            None
        } else {
            Some(PodStatus {
                pod_ips: Some(
                    pod_ips
                        .iter()
                        .map(|ip| PodIP { ip: ip.to_string() })
                        .collect(),
                ),
                pod_ip: pod_ips.first().map(ToString::to_string),
                ..Default::default()
            })
        };

        Pod {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                labels: Some(labels.into_iter().collect()),
                ..Default::default()
            },
            spec: Some(PodSpec {
                host_network: Some(host_network),
                ..Default::default()
            }),
            status,
        }
    }

    #[test]
    fn desired_slices_group_pods_by_sanitized_labels() {
        let ns = make_namespace(
            "default",
            [("env".to_string(), "test".to_string())]
                .into_iter()
                .collect(),
        );
        let pod_a = make_pod(
            "a",
            "default",
            [
                ("app".to_string(), "demo".to_string()),
                ("controller-revision-hash".to_string(), "abc".to_string()),
            ]
            .into_iter()
            .collect(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2))],
            false,
        );
        let pod_b = make_pod(
            "b",
            "default",
            [
                ("app".to_string(), "demo".to_string()),
                ("controller-revision-hash".to_string(), "def".to_string()),
            ]
            .into_iter()
            .collect(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 1, 0, 3))],
            false,
        );
        let pods = make_pod_store(vec![pod_a, pod_b]);

        let desired = desired_slices_for_namespace(&ns, &pods, "cluster2");
        assert_eq!(desired.len(), 1);

        let slice = &desired[0];
        assert!(slice.name_any().starts_with("cluster2-"));
        assert_eq!(slice.spec.cluster, "cluster2");
        assert_eq!(
            slice.spec.namespace_labels.get("env"),
            Some(&"test".to_string())
        );
        assert_eq!(slice.spec.pod_labels.get("app"), Some(&"demo".to_string()));
        assert!(
            !slice
                .spec
                .pod_labels
                .contains_key("controller-revision-hash")
        );
        assert_eq!(slice.spec.endpoints.len(), 2);
        let endpoint_ips: BTreeSet<IpAddr> = slice.spec.endpoints.iter().map(|ep| ep.ip).collect();
        assert!(endpoint_ips.contains(&IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2))));
        assert!(endpoint_ips.contains(&IpAddr::V4(Ipv4Addr::new(10, 1, 0, 3))));
    }

    #[test]
    fn desired_slices_keep_distinct_label_sets_separate() {
        let ns = make_namespace("default", HashMap::new());
        let pod_a = make_pod(
            "a",
            "default",
            [("app".to_string(), "demo-a".to_string())]
                .into_iter()
                .collect(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2))],
            false,
        );
        let pod_b = make_pod(
            "b",
            "default",
            [("app".to_string(), "demo-b".to_string())]
                .into_iter()
                .collect(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 1, 0, 3))],
            false,
        );
        let pods = make_pod_store(vec![pod_a, pod_b]);

        let desired = desired_slices_for_namespace(&ns, &pods, "cluster2");
        assert_eq!(desired.len(), 2);

        let apps: BTreeSet<String> = desired
            .iter()
            .filter_map(|slice| slice.spec.pod_labels.get("app").cloned())
            .collect();
        assert_eq!(
            apps,
            ["demo-a".to_string(), "demo-b".to_string()]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn desired_slices_skip_host_network_and_pending_pods() {
        let ns = make_namespace("default", HashMap::new());
        let host_network = make_pod(
            "hostnet",
            "default",
            [("app".to_string(), "demo".to_string())]
                .into_iter()
                .collect(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2))],
            true,
        );
        let pending = make_pod(
            "pending",
            "default",
            [("app".to_string(), "demo".to_string())]
                .into_iter()
                .collect(),
            vec![],
            false,
        );
        let pods = make_pod_store(vec![host_network, pending]);

        let desired = desired_slices_for_namespace(&ns, &pods, "cluster2");
        assert!(desired.is_empty());
    }

    #[test]
    fn pod_ips_uses_pod_ips_and_falls_back_to_pod_ip() {
        let pod_with_list = make_pod(
            "a",
            "default",
            [("app".to_string(), "demo".to_string())]
                .into_iter()
                .collect(),
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 3, 0, 2)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
            false,
        );
        let ips = pod_ips(&pod_with_list);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(10, 3, 0, 2))));
        assert!(ips.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));

        let mut pod_with_single = make_pod(
            "b",
            "default",
            [("app".to_string(), "demo".to_string())]
                .into_iter()
                .collect(),
            vec![],
            false,
        );
        pod_with_single.status = Some(PodStatus {
            pod_ips: None,
            pod_ip: Some("10.3.0.9".to_string()),
            ..Default::default()
        });
        let fallback_ips = pod_ips(&pod_with_single);
        assert_eq!(fallback_ips, vec![IpAddr::V4(Ipv4Addr::new(10, 3, 0, 9))]);
    }

    #[test]
    fn mesh_identity_slice_name_is_stable_for_same_input() {
        let labels: BTreeMap<String, String> = [("app".to_string(), "demo".to_string())]
            .into_iter()
            .collect();
        let first = mesh_identity_slice_name("cluster2", &labels);
        let second = mesh_identity_slice_name("cluster2", &labels);
        assert_eq!(first, second);
    }
}
