use std::{pin::pin, sync::Arc, time::Duration};

use ahash::{HashMap, HashMapExt};
use futures::StreamExt;
use k8s_openapi::Metadata;
use kube::{
    Resource,
    runtime::reflector::{ReflectHandle, Store},
};
use mesh_cni_k8s_utils::create_store_and_subscriber;
use serde::de::DeserializeOwned;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, warn};

use crate::{Result, kubernetes::cluster::Cluster};

pub struct MultiClusterState<K>
where
    K: Resource + Send + Clone + core::fmt::Debug + DeserializeOwned + Metadata + Sync + 'static,
    <K as Resource>::DynamicType: Default + Eq + Send + DeserializeOwned + core::hash::Hash + Clone,
{
    state: HashMap<String, Store<K>>,
    rx: Option<Receiver<Arc<K>>>,
}

impl<K> MultiClusterState<K>
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
            let Ok((store, subscriber)) =
                create_store_and_subscriber(api, Some(Duration::from_secs(30))).await
            else {
                warn!("failed to create store for cluster {}", cluster.name);
                continue;
            };
            state.insert(cluster.name.clone(), store);

            tokio::spawn(start_cluster_event_loop(subscriber, tx.clone()));
        }

        Ok(Self {
            state,
            rx: Some(rx),
        })
    }
    pub fn take_receiver(&mut self) -> Option<Receiver<Arc<K>>> {
        self.rx.take()
    }
}

async fn start_cluster_event_loop<K>(subscriber: ReflectHandle<K>, tx: Sender<Arc<K>>) -> Result<()>
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
    let mut stream = pin!(subscriber);
    while let Some(resource) = stream.next().await {
        if tx.send(resource).await.is_err() {
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
