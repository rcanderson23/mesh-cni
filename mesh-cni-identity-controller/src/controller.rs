use std::{fmt::Debug, sync::Arc, time::Duration};

use kube::{ResourceExt, runtime::controller::Action};
use serde::de::DeserializeOwned;
use tracing::error;

use crate::{Error, IdentityBpfState, IdentityControllerExt, Result, context::Context};

pub(crate) const DEFAULT_REQUEUE_DURATION: Duration = Duration::from_secs(300);
const ERROR_REQUEUE_DURATION: Duration = Duration::from_secs(5);

#[tracing::instrument(skip(ctx, k))]
pub(crate) async fn reconcile<K, B>(k: Arc<K>, ctx: Arc<Context<B>>) -> Result<Action>
where
    K: IdentityControllerExt,
    K: ResourceExt<DynamicType = ()>,
    K: DeserializeOwned + Clone + Sync + Debug + Send + 'static,
    B: IdentityBpfState,
{
    k.reconcile(ctx).await
}

// TODO: revisit error handling and backoff strategy once controller logic is defined.
pub(crate) fn error_policy<K, B>(k: Arc<K>, error: &Error, _ctx: Arc<Context<B>>) -> Action
where
    K: ResourceExt<DynamicType = ()>,
    K: DeserializeOwned + Clone + Send + Sync + std::fmt::Debug + 'static,
    B: IdentityBpfState,
{
    let name = k.name_any();
    let ns = k.namespace().unwrap_or_default();
    error!(?error, "reconcile error for {}/{}", ns, name);
    Action::requeue(ERROR_REQUEUE_DURATION)
}
