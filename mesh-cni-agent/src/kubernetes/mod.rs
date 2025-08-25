pub mod pod;
pub mod service;

use futures::StreamExt;
use k8s_openapi::serde::de::DeserializeOwned;
use kube::runtime::reflector::ReflectHandle;
use kube::runtime::{WatchStreamExt, reflector, watcher};
use kube::{Api, Resource};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::hash::Hash;
use std::net::IpAddr;
use tracing::{error, trace};

use crate::{Error, Result};

const LABEL_MESH_CLUSTER_ID: &str = "mesh.dev/cluster-id";

pub type ClusterId = u32;

pub enum PodIdentityEvent {
    Add(PodIdentity),
    Delete(IpAddr),
}

pub struct PodIdentity {
    pub labels: Labels,
    pub ips: Vec<IpAddr>,
    pub cluster_id: ClusterId,
}

// TODO: does this actually need seperateion between types of labels or should
// there be some prefixing to denote the label origin?
#[derive(Eq, Hash, PartialEq, Clone)]
pub struct Labels {
    pub namespace_labels: BTreeMap<String, String>,
    pub pod_labels: BTreeMap<String, String>,
    pub mesh_labels: BTreeMap<&'static str, String>,
}

impl Labels {
    pub fn to_hashmap(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for (k, v) in self.namespace_labels.iter() {
            map.insert(k.to_owned(), v.to_owned());
        }
        for (k, v) in self.pod_labels.iter() {
            map.insert(k.to_owned(), v.to_owned());
        }
        for (k, v) in self.mesh_labels.iter() {
            map.insert(k.to_string(), v.to_owned());
        }
        map
    }
}

fn selector_matches(
    selectors: &BTreeMap<String, String>,
    labels: &BTreeMap<String, String>,
) -> bool {
    for selector in selectors {
        let value = labels.get(selector.0);
        if value != Some(selector.1) {
            return false;
        }
    }
    true
}

async fn create_subscriber<K>(api: Api<K>) -> Result<ReflectHandle<K>>
where
    K: Resource + Send + Clone + Debug + DeserializeOwned + Sync + 'static,
    <K as Resource>::DynamicType: Default + Eq + Send + DeserializeOwned + Hash + Clone,
{
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
                    error!(%e, "unexepected error with stream")
                }
            }
        });

    tokio::spawn(stream);
    store
        .wait_until_ready()
        .await
        .map_err(|e| Error::StoreCreation(e.to_string()))?;
    Ok(subscriber)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_label_matcher() {
        let mut selectors = BTreeMap::new();
        let mut labels = BTreeMap::new();
        selectors.insert("kubernetes.io/metadata.name".into(), "kube-system".into());
        labels.insert("kubernetes.io/metadata.name".into(), "kube-system".into());
        assert!(selector_matches(&selectors, &labels));

        labels.insert("kubernetes.io/os".into(), "linux".into());
        assert!(selector_matches(&selectors, &labels));

        labels.insert("kubernetes.io/metadata.name".into(), "default".into());
        assert!(!selector_matches(&selectors, &labels));
    }
}
