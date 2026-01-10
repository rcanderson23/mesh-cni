use std::fmt::Debug;
use std::hash::Hash;

use futures::StreamExt;
use k8s_openapi::serde::de::DeserializeOwned;
use kube::runtime::reflector::{ReflectHandle, Store};
use kube::runtime::{WatchStreamExt, reflector, watcher};
use kube::{Api, Resource};
use thiserror::Error;
use tracing::{error, trace};

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to create store: {0}")]
    StoreCreation(String),

    #[error("kube error: {0}")]
    KubeError(#[from] kube::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn create_store_and_subscriber<K>(api: Api<K>) -> Result<(Store<K>, ReflectHandle<K>)>
where
    K: Resource + Send + Clone + Debug + DeserializeOwned + Sync + 'static,
    <K as Resource>::DynamicType: Default + Eq + Send + DeserializeOwned + Hash + Clone,
{
    // TODO: figure out an appropriate number here and get rid of magic number
    let (store, writer) = reflector::store_shared(1000);
    let subscriber: ReflectHandle<K> = writer
        .subscribe()
        .ok_or_else(|| Error::StoreCreation("failed to create subscriber".into()))?;

    let stream = watcher(api, watcher::Config::default())
        .default_backoff()
        .reflect_shared(writer)
        .for_each(|res| async move {
            match res {
                Ok(ev) => trace!("received event: {:?}", ev),
                Err(e) => {
                    error!(%e, "unexpected error with stream")
                }
            }
        });

    tokio::spawn(stream);
    store
        .wait_until_ready()
        .await
        .map_err(|e| Error::StoreCreation(e.to_string()))?;
    Ok((store, subscriber))
}
