use std::{collections::HashSet, sync::Arc};

use futures::StreamExt;
use k8s_openapi::api::{
    core::v1::{Namespace, Pod},
    networking::v1::NetworkPolicy,
};
use kube::{
    Api, Client, ResourceExt,
    runtime::{Config, Controller, reflector::ObjectRef},
};
use mesh_cni_crds::v1alpha1::{
    cidridentity::CIDRIdentity, identity::Identity, meshidentityslice::MeshIdentitySlice,
};
use mesh_cni_k8s_utils::create_store_and_touched_subscriber;
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

use crate::{
    Error, PolicyDataplane, Result,
    context::{Context, RulesetState},
    controller::error_policy,
    identity::reconcile_policy_with_identity,
    selector::{
        egress_rules_select_identity, ingress_rules_select_identity, policy_selects_identity,
    },
};

pub async fn start_policy_controllers<P>(
    client: Client,
    policy_bpf_state: P,
    cancel: CancellationToken,
) -> Result<Arc<Context<P>>>
where
    P: PolicyDataplane + Send + Sync + 'static,
{
    let store_init = timeout(Duration::from_secs(30), async {
        tokio::try_join!(
            create_store_and_touched_subscriber(
                Api::all(client.clone()),
                kube::runtime::watcher::Config::default(),
                Some(Duration::from_secs(30))
            ),
            create_store_and_touched_subscriber(
                Api::all(client.clone()),
                kube::runtime::watcher::Config::default(),
                Some(Duration::from_secs(30))
            ),
            create_store_and_touched_subscriber(
                Api::all(client.clone()),
                kube::runtime::watcher::Config::default(),
                Some(Duration::from_secs(30))
            ),
            create_store_and_touched_subscriber(
                Api::all(client.clone()),
                kube::runtime::watcher::Config::default(),
                Some(Duration::from_secs(30))
            ),
            create_store_and_touched_subscriber(
                Api::all(client.clone()),
                kube::runtime::watcher::Config::default(),
                Some(Duration::from_secs(30))
            ),
            create_store_and_touched_subscriber(
                Api::all(client.clone()),
                kube::runtime::watcher::Config::default(),
                Some(Duration::from_secs(30))
            ),
        )
    })
    .await
    .map_err(|_| Error::Timeout("store initialization".into()))??;

    let (
        (pod_store, pod_subscriber),
        (policy_store, policy_subscriber),
        (identity_store, identity_subscriber),
        (cidr_identity_store, cidr_identity_subscriber),
        (_namespace_store, namespace_subscriber),
        (mesh_identity_slice_store, mesh_identity_slice_subscriber),
    ) = store_init;

    let index_state = policy_bpf_state.policy_index_state()?;
    let cidr_state = policy_bpf_state.policy_cidr_index_state()?;
    let ruleset_state = policy_bpf_state.policy_ruleset_state()?;
    let ruleset_state = RulesetState::new_with_cidr(&index_state, &cidr_state, &ruleset_state);

    let context = Arc::new(Context {
        pod_store: pod_store.clone(),
        policy_store: policy_store.clone(),
        identity_store: identity_store.clone(),
        cidr_identity_store: cidr_identity_store.clone(),
        mesh_identity_slice_store: mesh_identity_slice_store.clone(),
        policy_bpf_state,
        ruleset_state,
    });

    let mapper_netpol_identity_store = identity_store.clone();
    let mapper_pod_identity_store = identity_store.clone();
    let mapper_pod_policy_store = policy_store.clone();
    let mapper_identity_policy_store = policy_store.clone();
    let mapper_identity_identity_store = identity_store.clone();
    let mapper_cidr_identity_identity_store = identity_store.clone();
    let mapper_mesh_identity_slice_identity_store = identity_store.clone();
    let mapper_namespace_identity_store = identity_store.clone();
    let mapper_namespace_policy_store = policy_store.clone();

    let policy_mapper = move |policy: Arc<NetworkPolicy>| -> Vec<ObjectRef<Identity>> {
        let policy_ns = policy.namespace();
        // It is is possible on delete that the spec will not be present so we will do best effort
        // reconcile by reconciling all network policies in the namespace.
        if policy.spec.is_none() {
            return mapper_netpol_identity_store
                .state()
                .iter()
                .filter_map(|i| {
                    if let (Some(ns), Some(policy_ns)) = (i.namespace(), policy_ns.as_deref())
                        && ns == policy_ns
                    {
                        return Some(ObjectRef::new(&i.name_any()).within(&ns));
                    }
                    None
                })
                .collect();
        }

        mapper_netpol_identity_store
            .state()
            .iter()
            .filter_map(|i| {
                if !ingress_rules_select_identity(i, policy.as_ref()).is_empty()
                    || !egress_rules_select_identity(i, policy.as_ref()).is_empty()
                    || policy_selects_identity(policy.as_ref(), i)
                {
                    Some(ObjectRef::new(&i.name_any()).within(&i.namespace()?))
                } else {
                    None
                }
            })
            .collect()
    };

    let pod_mapper = move |pod: Arc<Pod>| -> Vec<ObjectRef<Identity>> {
        let identities = mapper_pod_identity_store.state();
        let policies = mapper_pod_policy_store.state();
        let dynamic_peer_policies: Vec<&Arc<NetworkPolicy>> = policies
            .iter()
            .filter(|p| policy_has_dynamic_peer_resolution(p))
            .collect();

        let mut refs = Vec::new();
        let mut seen: HashSet<(String, String)> = HashSet::new();

        // Existing behavior: pod events should reconcile matching identities in the same namespace.
        for identity in &identities {
            let Some(ns) = identity.namespace() else {
                continue;
            };
            if Some(ns.as_str()) != pod.namespace().as_deref() {
                continue;
            }
            if !identity.pod_labels_match(pod.as_ref()) {
                continue;
            }
            let key = (ns.clone(), identity.name_any());
            if seen.insert(key) {
                refs.push(ObjectRef::new(&identity.name_any()).within(&ns));
            }
        }

        // Correctness-first fanout: pod churn can alter peer membership for selected identities
        // when policies use peer selectors or ipBlocks.
        if pod_has_ips(pod.as_ref()) && !dynamic_peer_policies.is_empty() {
            for identity in &identities {
                if dynamic_peer_policies
                    .iter()
                    .any(|policy| policy_selects_identity(policy, identity))
                {
                    let Some(ns) = identity.namespace() else {
                        continue;
                    };
                    let key = (ns.clone(), identity.name_any());
                    if seen.insert(key) {
                        refs.push(ObjectRef::new(&identity.name_any()).within(&ns));
                    }
                }
            }
        }

        refs
    };

    // Correctness-first fanout: identity churn can alter peer membership (label/IP changes)
    // for selected identities across policies with dynamic peer resolution.
    let identity_mapper = move |_identity: Arc<Identity>| -> Vec<ObjectRef<Identity>> {
        let identities = mapper_identity_identity_store.state();
        let policies = mapper_identity_policy_store.state();
        let dynamic_peer_policies: Vec<&Arc<NetworkPolicy>> = policies
            .iter()
            .filter(|p| policy_has_dynamic_peer_resolution(p))
            .collect();

        if dynamic_peer_policies.is_empty() {
            return Vec::new();
        }

        identities
            .iter()
            .filter_map(|identity| {
                if dynamic_peer_policies
                    .iter()
                    .any(|policy| policy_selects_identity(policy, identity))
                {
                    Some(ObjectRef::new(&identity.name_any()).within(&identity.namespace()?))
                } else {
                    None
                }
            })
            .collect()
    };

    // Namespace label/name changes can alter namespaceSelector peer resolution.
    // Correctness-first fanout: reconcile selected identities for all policies using namespace selectors.
    let namespace_mapper = move |_namespace: Arc<Namespace>| -> Vec<ObjectRef<Identity>> {
        let identities = mapper_namespace_identity_store.state();
        let policies = mapper_namespace_policy_store.state();
        let namespace_selector_policies: Vec<&Arc<NetworkPolicy>> = policies
            .iter()
            .filter(|p| policy_has_namespace_selector(p))
            .collect();

        if namespace_selector_policies.is_empty() {
            return Vec::new();
        }

        identities
            .iter()
            .filter_map(|identity| {
                if namespace_selector_policies
                    .iter()
                    .any(|policy| policy_selects_identity(policy, identity))
                {
                    Some(ObjectRef::new(&identity.name_any()).within(&identity.namespace()?))
                } else {
                    None
                }
            })
            .collect()
    };

    // A CIDRIdentity update can change policy peer IDs for any identity selected by any policy.
    // Reconcile all identities on CIDRIdentity changes to converge quickly.
    let cidr_identity_mapper =
        move |_cidr_identity: Arc<CIDRIdentity>| -> Vec<ObjectRef<Identity>> {
            mapper_cidr_identity_identity_store
                .state()
                .iter()
                .filter_map(|i| Some(ObjectRef::new(&i.name_any()).within(&i.namespace()?)))
                .collect()
        };
    let mesh_identity_slice_mapper =
        move |_slice: Arc<MeshIdentitySlice>| -> Vec<ObjectRef<Identity>> {
            mapper_mesh_identity_slice_identity_store
                .state()
                .iter()
                .filter_map(|i| Some(ObjectRef::new(&i.name_any()).within(&i.namespace()?)))
                .collect()
        };

    let config = Config::default();
    let config = config.debounce(Duration::from_millis(500));
    let config = config.concurrency(10);

    let identity_trigger = identity_subscriber.clone();

    tokio::spawn(
        Controller::for_shared_stream(identity_subscriber, identity_store)
            .with_config(config)
            .watches_shared_stream(policy_subscriber, policy_mapper)
            .watches_shared_stream(pod_subscriber, pod_mapper)
            .watches_shared_stream(identity_trigger, identity_mapper)
            .watches_shared_stream(cidr_identity_subscriber, cidr_identity_mapper)
            .watches_shared_stream(namespace_subscriber, namespace_mapper)
            .watches_shared_stream(mesh_identity_slice_subscriber, mesh_identity_slice_mapper)
            .graceful_shutdown_on(shutdown(cancel))
            .run(
                reconcile_policy_with_identity,
                error_policy,
                context.clone(),
            )
            .filter_map(|x| async move { std::result::Result::ok(x) })
            .for_each(|_| futures::future::ready(())),
    );

    Ok(context)
}

async fn shutdown(cancel: CancellationToken) {
    cancel.cancelled().await;
}

fn policy_has_namespace_selector(policy: &NetworkPolicy) -> bool {
    let Some(spec) = policy.spec.as_ref() else {
        return false;
    };

    if spec.ingress.as_ref().is_some_and(|rules| {
        rules.iter().any(|rule| {
            rule.from
                .as_ref()
                .is_some_and(|peers| peers.iter().any(|peer| peer.namespace_selector.is_some()))
        })
    }) {
        return true;
    }

    spec.egress.as_ref().is_some_and(|rules| {
        rules.iter().any(|rule| {
            rule.to
                .as_ref()
                .is_some_and(|peers| peers.iter().any(|peer| peer.namespace_selector.is_some()))
        })
    })
}

fn policy_has_dynamic_peer_resolution(policy: &NetworkPolicy) -> bool {
    let Some(spec) = policy.spec.as_ref() else {
        return false;
    };

    if spec.ingress.as_ref().is_some_and(|rules| {
        rules.iter().any(|rule| {
            rule.from.as_ref().is_some_and(|peers| {
                peers.iter().any(|peer| {
                    peer.ip_block.is_some()
                        || peer.namespace_selector.is_some()
                        || peer.pod_selector.is_some()
                })
            })
        })
    }) {
        return true;
    }

    spec.egress.as_ref().is_some_and(|rules| {
        rules.iter().any(|rule| {
            rule.to.as_ref().is_some_and(|peers| {
                peers.iter().any(|peer| {
                    peer.ip_block.is_some()
                        || peer.namespace_selector.is_some()
                        || peer.pod_selector.is_some()
                })
            })
        })
    })
}

fn pod_has_ips(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|status| status.pod_ips.as_ref())
        .is_some_and(|ips| !ips.is_empty())
}
