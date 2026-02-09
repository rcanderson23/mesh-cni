use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::{core::v1::Pod, networking::v1::NetworkPolicy};
use kube::{
    Api, Client, ResourceExt,
    runtime::{Config, Controller, reflector::ObjectRef, watcher::Config as WatcherConfig},
};
use mesh_cni_crds::v1alpha1::identity::Identity;
use mesh_cni_k8s_utils::create_store_and_subscriber;
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

use crate::{
    Error, PolicyControllerBpf, Result,
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
    P: PolicyControllerBpf + Send + Sync + 'static,
{
    let store_init = timeout(Duration::from_secs(30), async {
        tokio::try_join!(
            create_store_and_subscriber(Api::all(client.clone()), Some(Duration::from_secs(30))),
            create_store_and_subscriber(Api::all(client.clone()), Some(Duration::from_secs(30))),
            create_store_and_subscriber(Api::all(client.clone()), Some(Duration::from_secs(30))),
        )
    })
    .await
    .map_err(|_| Error::Timeout("store initialization".into()))??;

    let ((pod_store, _), (policy_store, _), (identity_store, identity_subscriber)) = store_init;

    let index_state = policy_bpf_state.index_state()?;
    let ruleset_state = policy_bpf_state.ruleset_state()?;
    let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

    let context = Arc::new(Context {
        pod_store: pod_store.clone(),
        policy_store: policy_store.clone(),
        identity_store: identity_store.clone(),
        policy_bpf_state,
        ruleset_state,
    });

    let mapper_netpol_identity_store = identity_store.clone();
    let mapper_pod_identity_store = identity_store.clone();

    let policy_mapper = move |policy: NetworkPolicy| -> Vec<ObjectRef<Identity>> {
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
                if !ingress_rules_select_identity(i, &policy).is_empty()
                    || !egress_rules_select_identity(i, &policy).is_empty()
                    || policy_selects_identity(&policy, i)
                {
                    Some(ObjectRef::new(&i.name_any()).within(&i.namespace()?))
                } else {
                    None
                }
            })
            .collect()
    };

    let pod_mapper = move |pod: Pod| -> Vec<ObjectRef<Identity>> {
        mapper_pod_identity_store
            .state()
            .iter()
            .filter_map(|i| {
                let ns = i.namespace()?;
                if ns != pod.namespace()? {
                    return None;
                }
                if i.pod_labels_match(&pod) {
                    Some(ObjectRef::new(&i.name_any()).within(&ns))
                } else {
                    None
                }
            })
            .collect()
    };

    let config = Config::default();
    let config = config.debounce(Duration::from_millis(500));
    let config = config.concurrency(10);

    tokio::spawn(
        Controller::for_shared_stream(identity_subscriber, identity_store)
            .with_config(config)
            .watches(
                Api::all(client.clone()), // ReflectHandles does not pass delete events so we have
                // to create another client here
                WatcherConfig::default(),
                policy_mapper,
            )
            .watches(
                Api::all(client.clone()),
                WatcherConfig::default(),
                pod_mapper,
            )
            // .watches_shared_stream(pod_subscriber, pod_mapper)
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
