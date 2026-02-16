use std::{collections::HashSet, sync::Arc, time::Duration};

use kube::{ResourceExt, runtime::controller::Action};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::{Error, context::Context};

pub(crate) const MANANGER: &str = "identity-gen-controller";

pub(crate) fn error_policy<K>(k: Arc<K>, error: &Error, _ctx: Arc<Context>) -> Action
where
    K: ResourceExt<DynamicType = ()>,
    K: DeserializeOwned + Clone + Send + Sync + std::fmt::Debug + 'static,
{
    let name = k.name_any();
    let ns = k.namespace().unwrap_or_default();
    tracing::error!(?error, "reconcile error for {}/{}", ns, name);
    Action::requeue(Duration::from_secs(1))
}

pub(crate) fn hash_input_name<T: Serialize>(value: &T) -> crate::Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::HashConversionFailure)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

pub(crate) fn used_identity_ids(ctx: &Context) -> HashSet<u32> {
    let mut ids = HashSet::new();
    for identity in ctx.identities.state() {
        ids.insert(identity.spec.id);
    }
    ids
}

pub(crate) fn used_cidr_identity_ids(ctx: &Context) -> HashSet<u32> {
    let mut ids = HashSet::new();
    for identity in ctx.cidr_identities.state() {
        ids.insert(identity.spec.id);
    }
    ids
}
