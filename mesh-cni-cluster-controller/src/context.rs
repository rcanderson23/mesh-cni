use std::{collections::BTreeMap, sync::RwLock};

use k8s_openapi::api::core::v1::Secret;
use kube::{Client, runtime::reflector::Store};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[allow(unused)]
pub struct Context {
    pub client: Client,
    pub namespace: String,
    pub secrets: Store<Secret>,
    /// Stores cancellation tokens for shutting down child controllers
    /// when the cluster is deleted
    pub controllers: RwLock<BTreeMap<String, (CancellationToken, JoinHandle<()>)>>,
}
