use std::pin::pin;
use std::sync::Arc;

use ahash::{HashMap, HashMapExt};
use futures::StreamExt;
use k8s_openapi::Metadata;
use kube::core::{Selector, SelectorExt};
use kube::runtime::reflector::{ObjectRef, ReflectHandle, Store};
use kube::{Resource, ResourceExt};
use serde::de::DeserializeOwned;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, warn};

use crate::Result;
use crate::kubernetes::cluster::Cluster;
use mesh_cni_k8s_utils::create_store_and_subscriber;

pub trait MultiClusterStore<K>
where
    K: k8s_openapi::Metadata + kube::Resource + Clone,
    K::DynamicType: std::hash::Hash + std::cmp::Eq + Clone,
{
    fn get_from_cluster(&self, obj_ref: &ObjectRef<K>, cluster_name: &str) -> Option<Arc<K>>;
    fn get_all(&self, obj_ref: &ObjectRef<K>) -> Vec<Arc<K>>;
    fn get_all_by_namespace_label(
        &self,
        namespace: Option<&str>,
        selector: &Selector,
    ) -> Vec<Arc<K>>;
}

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
            let Ok((store, subscriber)) = create_store_and_subscriber(api).await else {
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

impl<K> MultiClusterStore<K> for MultiClusterState<K>
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
    fn get_from_cluster(&self, obj_ref: &ObjectRef<K>, cluster_name: &str) -> Option<Arc<K>> {
        let store = self.state.get(cluster_name)?;
        store.get(obj_ref)
    }

    fn get_all(&self, obj_ref: &ObjectRef<K>) -> Vec<Arc<K>> {
        let mut result = vec![];
        for (_, store) in self.state.iter() {
            let Some(o) = store.get(obj_ref) else {
                continue;
            };
            result.push(o);
        }
        result
    }

    fn get_all_by_namespace_label(
        &self,
        namespace: Option<&str>,
        selector: &Selector,
    ) -> Vec<Arc<K>> {
        let mut result = Vec::new();
        for state in self.state.values() {
            for k in state.state().iter() {
                if selector.matches(k.labels()) && k.namespace().as_deref() == namespace {
                    result.push(k.clone());
                }
            }
        }
        result
    }
}

impl<K> MultiClusterStore<K> for Store<K>
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
    fn get_from_cluster(&self, obj_ref: &ObjectRef<K>, _cluster_name: &str) -> Option<Arc<K>> {
        self.get(obj_ref)
    }

    fn get_all(&self, obj_ref: &ObjectRef<K>) -> Vec<Arc<K>> {
        let Some(resource) = self.get(obj_ref) else {
            return Vec::new();
        };
        vec![resource]
    }

    fn get_all_by_namespace_label(
        &self,
        namespace: Option<&str>,
        selector: &Selector,
    ) -> Vec<Arc<K>> {
        let mut result = Vec::new();
        for item in self.state().iter() {
            if item.namespace().as_deref() == namespace && selector.matches(item.labels()) {
                result.push(item.clone());
            }
        }
        result
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
