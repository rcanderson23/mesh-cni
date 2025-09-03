use std::pin::pin;
use std::sync::Arc;

use ahash::{HashMap, HashMapExt};
use futures::StreamExt;
use k8s_openapi::Metadata;
use kube::Resource;
use kube::runtime::reflector::{ObjectRef, ReflectHandle, Store};
use serde::de::DeserializeOwned;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, warn};

use crate::Result;
use crate::kubernetes::cluster::Cluster;
use crate::kubernetes::{ClusterId, create_store_and_subscriber};

pub trait GlobalStore<K>
where
    K: k8s_openapi::Metadata + kube::Resource + Clone,
    K::DynamicType: std::hash::Hash + std::cmp::Eq + Clone,
{
    fn get_from_cluster(&self, obj_ref: &ObjectRef<K>, cluster_name: &str) -> Vec<Arc<K>>;
    fn get_all(&self, obj_ref: &ObjectRef<K>) -> Vec<Arc<K>>;
}

pub struct GlobalState<K>
where
    K: Resource + Send + Clone + core::fmt::Debug + DeserializeOwned + Metadata + Sync + 'static,
    <K as Resource>::DynamicType: Default + Eq + Send + DeserializeOwned + core::hash::Hash + Clone,
{
    state: HashMap<ClusterId, Store<K>>,
    rx: Option<Receiver<ClusterEvent<K>>>,
}

impl<K> GlobalState<K>
where
    K: Resource
        + Send
        + Clone
        + core::fmt::Debug
        + DeserializeOwned
        + k8s_openapi::Metadata
        + Sync
        + 'static,
    <K as Resource>::DynamicType: Default + Eq + Send + DeserializeOwned + core::hash::Hash + Clone,
{
    pub async fn try_new(clusters: Vec<Cluster>) -> Result<Self> {
        // TODO: fix magic number
        let (tx, rx) = tokio::sync::mpsc::channel(1000);

        let mut state = HashMap::new();
        for mut cluster in clusters {
            let Some(client) = cluster.take_client() else {
                warn!("failed to get client for cluster {}", cluster.name);
                continue;
            };

            let api = kube::Api::all(client);
            let Ok((store, subscriber)) = create_store_and_subscriber(api).await else {
                warn!("failed to create store for cluster {}", cluster.name);
                continue;
            };
            state.insert(cluster.id, store);

            // TODO: handle this?
            tokio::spawn(start_cluster_event_loop(cluster, subscriber, tx.clone()));
        }

        Ok(Self {
            state,
            rx: Some(rx),
        })
    }
    pub fn take_receiver(&mut self) -> Option<Receiver<ClusterEvent<K>>> {
        self.rx.take()
    }
}

async fn start_cluster_event_loop<K>(
    cluster: Cluster,
    subscriber: ReflectHandle<K>,
    tx: Sender<ClusterEvent<K>>,
) -> Result<()>
where
    K: Resource
        + Send
        + Clone
        + core::fmt::Debug
        + DeserializeOwned
        + k8s_openapi::Metadata
        + Sync
        + 'static,
    <K as Resource>::DynamicType: Default + Eq + Send + DeserializeOwned + core::hash::Hash + Clone,
{
    let cluster = Arc::new(cluster);
    let mut stream = pin!(subscriber);
    while let Some(resource) = stream.next().await {
        if tx
            .send(ClusterEvent {
                cluster: cluster.clone(),
                resource,
            })
            .await
            .is_err()
        {
            error!("failed to send event as reciever has been dropped");
            break;
        }
    }
    Ok(())
}

pub struct ClusterEvent<K> {
    pub cluster: Arc<Cluster>,
    pub resource: Arc<K>,
}
