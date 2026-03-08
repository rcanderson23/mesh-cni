use std::{sync::Arc, time::Duration};

use kube::{ResourceExt, runtime::controller::Action};
use serde::de::DeserializeOwned;
use tracing::error;

use crate::{Error, context::Context};

pub(crate) const DEFAULT_REQUEUE_DURATION: Duration = Duration::from_secs(300);
const ERROR_REQUEUE_DURATION: Duration = Duration::from_secs(5);

// TODO: revisit error handling and backoff strategy once controller logic is defined.
pub(crate) fn error_policy<K, P>(k: Arc<K>, error: &Error, _ctx: Arc<Context<P>>) -> Action
where
    K: ResourceExt<DynamicType = ()>,
    K: DeserializeOwned + Clone + Send + Sync + std::fmt::Debug + 'static,
{
    let name = k.name_any();
    let ns = k.namespace().unwrap_or_default();
    error!(?error, "reconcile error for {}/{}", ns, name);
    Action::requeue(ERROR_REQUEUE_DURATION)
}
