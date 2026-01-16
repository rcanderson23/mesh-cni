use std::{sync::Arc, time::Duration};

use k8s_openapi::api::{
    core::v1::{Namespace, Pod},
    networking::v1::NetworkPolicy,
};
use kube::{ResourceExt, runtime::controller::Action};
use serde::de::DeserializeOwned;
use tracing::info;

use crate::{Error, Result, context::Context};

const DEFAULT_REQUEUE_DURATION: Duration = Duration::from_secs(300);

#[tracing::instrument(skip(ctx, pod))]
pub(crate) async fn reconcile_pod(pod: Arc<Pod>, ctx: Arc<Context>) -> Result<Action> {
    let name = pod.name_any();
    let ns = pod.namespace().unwrap_or_default();
    info!("started reconciling Pod {}/{}", ns, name);
    let _ = ctx;
    Ok(Action::await_change())
}

#[tracing::instrument(skip(ctx, policy))]
pub(crate) async fn reconcile_policy(
    policy: Arc<NetworkPolicy>,
    ctx: Arc<Context>,
) -> Result<Action> {
    let name = policy.name_any();
    let ns = policy.namespace().unwrap_or_default();
    info!("started reconciling NetworkPolicy {}/{}", ns, name);
    let _ = ctx;
    Ok(Action::await_change())
}

#[tracing::instrument(skip(ctx, namespace))]
pub(crate) async fn reconcile_namespace(
    namespace: Arc<Namespace>,
    ctx: Arc<Context>,
) -> Result<Action> {
    let name = namespace.name_any();
    info!("started reconciling Namespace {}", name);
    let _ = ctx;
    Ok(Action::await_change())
}

// TODO: revisit error handling and backoff strategy once controller logic is defined.
pub(crate) fn error_policy<K>(k: Arc<K>, error: &Error, _ctx: Arc<Context>) -> Action
where
    K: ResourceExt<DynamicType = ()>,
    K: DeserializeOwned + Clone + Send + Sync + std::fmt::Debug + 'static,
{
    let name = k.name_any();
    let ns = k.namespace().unwrap_or_default();
    tracing::error!(?error, "reconcile error for {}/{}", ns, name);
    Action::requeue(DEFAULT_REQUEUE_DURATION)
}
