use std::collections::BTreeMap;
use std::fmt::Debug;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use aya::maps::lpm_trie::Key as LpmKey;
use k8s_openapi::api::core::v1::{Namespace, Pod};
use kube::runtime::reflector::ObjectRef;
use kube::{ResourceExt, runtime::controller::Action};
use mesh_cni_common::Id;
use serde::de::DeserializeOwned;
use tracing::{info, warn};

use crate::bpf::BpfMap;
use crate::kubernetes::Labels;
use crate::kubernetes::controllers::DEFAULT_REQUEUE_DURATION;
use crate::kubernetes::controllers::ip::context::Context;
use crate::kubernetes::{ClusterId, LABEL_MESH_CLUSTER_ID};
use crate::{Error, Result};

pub(crate) async fn reconcile_pod<IP4, IP6>(
    pod: Arc<Pod>,
    ctx: Arc<Context<IP4, IP6>>,
) -> Result<Action>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = Id>,
    IP6: BpfMap<Key = LpmKey<u128>, Value = Id>,
{
    let name = pod.name_any();
    let Some(ns) = pod.namespace() else {
        warn!("failed to find namespace on Pod {}", name);
        return Ok(Action::await_change());
    };
    info!("started reconciling Pod {}/{}", ns, name);

    if pod_is_host_network(&pod) {
        return Ok(Action::requeue(DEFAULT_REQUEUE_DURATION));
    }

    let ips = pod_ips(&pod);

    if ips.is_empty() {
        return Ok(Action::requeue(DEFAULT_REQUEUE_DURATION));
    }

    if pod.metadata.deletion_timestamp.is_some() {
        for ip in ips {
            // TODO: check error type on delete for 'NOTEXISTS'
            ctx.ip_state.delete(ip)?;
        }
        return Ok(Action::await_change());
    }

    let Some(namespace) = ctx.ns_store.get(&ObjectRef::new(&ns)) else {
        return Err(Error::ReconcileError("failed to find namespace".into()));
    };

    let labels = pod_labels(&pod, &namespace, ctx.cluster_id);
    for ip in ips {
        ctx.ip_state.insert(ip, &labels)?;
    }
    Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
}

pub(crate) async fn reconcile_namespace<IP4, IP6>(
    namespace: Arc<Namespace>,
    ctx: Arc<Context<IP4, IP6>>,
) -> Result<Action>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = Id>,
    IP6: BpfMap<Key = LpmKey<u128>, Value = Id>,
{
    let name = namespace.name_any();
    info!("started reconciling Namespace {}", name);
    let pods: Vec<Arc<Pod>> = ctx
        .pod_store
        .state()
        .iter()
        .filter(|p| (p.namespace().as_ref() == Some(&name) && !pod_is_host_network(p)))
        .map(|p| p.to_owned())
        .collect();
    for pod in pods {
        let ips = pod_ips(&pod);
        let labels = pod_labels(&pod, &namespace, ctx.cluster_id);
        for ip in ips {
            ctx.ip_state.insert(ip, &labels)?;
        }
    }

    Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
}

// TODO: fix error coditions and potentially make generic for all controllers
// TODO: make it exponentially backoff similar to controller-runtime
pub fn error_policy<K, IP4, IP6>(_k: Arc<K>, _error: &Error, _ctx: Arc<Context<IP4, IP6>>) -> Action
where
    K: ResourceExt<DynamicType = ()>,
    K: DeserializeOwned + Clone + Sync + Debug + Send + 'static,
    IP4: BpfMap<Key = LpmKey<u32>, Value = Id>,
    IP6: BpfMap<Key = LpmKey<u128>, Value = Id>,
{
    Action::requeue(DEFAULT_REQUEUE_DURATION)
}

fn pod_ips(pod: &Pod) -> Vec<IpAddr> {
    let Some(status) = pod.status.as_ref() else {
        return vec![];
    };

    let Some(ips) = status.pod_ips.as_ref() else {
        return vec![];
    };
    ips.iter()
        .filter_map(|ip| IpAddr::from_str(&ip.ip).ok())
        .collect()
}

fn pod_labels(pod: &Pod, ns: &Namespace, id: ClusterId) -> Labels {
    let mut mesh_labels = BTreeMap::new();
    mesh_labels.insert(LABEL_MESH_CLUSTER_ID, id.to_string());
    Labels {
        pod_labels: pod.labels().to_owned(),
        namespace_labels: ns.labels().to_owned(),
        mesh_labels,
    }
}

fn pod_is_host_network(pod: &Pod) -> bool {
    let Some(spec) = pod.spec.as_ref() else {
        return false;
    };
    spec.host_network.unwrap_or_default()
}
