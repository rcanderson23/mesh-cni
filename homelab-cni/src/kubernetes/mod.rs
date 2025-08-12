use futures::StreamExt;
use k8s_openapi::api::core::v1::{Namespace, Pod};
use k8s_openapi::serde::de::DeserializeOwned;
use kube::runtime::reflector::{ObjectRef, ReflectHandle};
use kube::runtime::{WatchStreamExt, reflector, watcher};
use kube::{Api, Resource, ResourceExt};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::net::IpAddr;
use std::pin::pin;
use std::str::FromStr;
use std::sync::Arc;
use tokio::select;
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, info, trace};

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

pub struct NamespacePodState {
    pub pod_subscriber: ReflectHandle<Pod>,
    pub namespace_subscriber: ReflectHandle<Namespace>,
    pub cluster_id: ClusterId,
    tx: Sender<PodIdentityEvent>,
}

impl NamespacePodState {
    pub async fn try_new(
        client: kube::Client,
        cluster_id: ClusterId,
        tx: Sender<PodIdentityEvent>,
    ) -> Result<Self> {
        let pod: Api<Pod> = Api::all(client.clone());
        let namespace: Api<Namespace> = Api::all(client);

        let pod_subscriber = create_subscriber(pod).await?;
        let namespace_subscriber = create_subscriber(namespace).await?;

        Ok(Self {
            pod_subscriber,
            namespace_subscriber,
            cluster_id,
            tx,
        })
    }

    pub async fn start(&self) -> Result<()> {
        let ns_store = self.namespace_subscriber.reader();
        let pod_store = self.pod_subscriber.reader();

        let ns_handle = async {
            let ns_stream = self.namespace_subscriber.clone();
            let mut ns_stream = pin!(ns_stream);

            info!("started namespace watch");
            while let Some(ns) = ns_stream.next().await {
                debug!("encountered namespace update for {}", ns.name_any());
                let pods: Vec<Arc<Pod>> = pod_store
                    .state()
                    .iter()
                    .filter(|p| (p.namespace() == Some(ns.name_any()) && !pod_is_host_network(p)))
                    .map(|p| p.to_owned())
                    .collect();
                for pod in pods {
                    let ips = pod_ips(&pod);
                    let labels = pod_labels(&pod, &ns, self.cluster_id);
                    if let Err(e) = self
                        .tx
                        .send(PodIdentityEvent::Add(PodIdentity {
                            labels,
                            ips,
                            cluster_id: self.cluster_id,
                        }))
                        .await
                    {
                        error!(%e, "failed to send add event");
                        return;
                    }
                }
            }
        };

        let pod_handle = async {
            let pod_stream = self.pod_subscriber.clone();
            let mut pod_stream = pin!(pod_stream);

            info!("started pod watch");
            while let Some(pod) = pod_stream.next().await {
                debug!("encountered pod update for {}", pod.name_any());
                if pod_is_host_network(&pod) {
                    continue;
                }
                let ips = pod_ips(&pod);

                if pod.metadata.deletion_timestamp.is_some() {
                    for ip in ips {
                        if let Err(e) = self.tx.send(PodIdentityEvent::Delete(ip)).await {
                            error!(%e, "failed to send delete event");
                            return;
                        }
                    }
                } else {
                    let Some(ns) =
                        ns_store.get(&ObjectRef::new(&pod.namespace().unwrap_or_default()))
                    else {
                        // if for some reason the namespace isn't present we will get pods on the
                        // namespace update stream
                        continue;
                    };
                    let labels = pod_labels(&pod, &ns, self.cluster_id);
                    let id = PodIdentity {
                        labels,
                        ips,
                        cluster_id: self.cluster_id,
                    };
                    if let Err(e) = self.tx.send(PodIdentityEvent::Add(id)).await {
                        error!(%e, "failed to send delete event");
                        return;
                    }
                }
            }
        };
        select! {
            _ = ns_handle => {},
            _= pod_handle => {},
        }

        Ok(())
    }

    pub fn namespaces_by_selectors(
        &self,
        selectors: &BTreeMap<String, String>,
    ) -> Vec<Arc<Namespace>> {
        self.namespace_subscriber
            .reader()
            .state()
            .iter()
            .filter(|ns| selector_matches(selectors, ns.labels()))
            .map(|ns| ns.to_owned())
            .collect()
    }
}

#[derive(Eq, Hash, PartialEq, Clone)]
pub struct Labels {
    pub namespace_labels: BTreeMap<String, String>,
    pub pod_labels: BTreeMap<String, String>,
    pub mesh_labels: BTreeMap<&'static str, String>,
}

fn pod_ips(pod: &Pod) -> Vec<IpAddr> {
    let Some(status) = pod.status.as_ref() else {
        return vec![];
    };

    let Some(ips) = status.pod_ips.as_ref() else {
        return vec![];
    };
    ips.iter()
        .filter_map(|ip| IpAddr::from_str(&ip.ip).ok())
        .collect()
}

fn pod_labels(pod: &Pod, ns: &Namespace, id: ClusterId) -> Labels {
    let mut mesh_labels = BTreeMap::new();
    mesh_labels.insert(LABEL_MESH_CLUSTER_ID, id.to_string());
    Labels {
        pod_labels: pod.labels().to_owned(),
        namespace_labels: ns.labels().to_owned(),
        mesh_labels,
    }
}

fn pod_is_host_network(pod: &Pod) -> bool {
    let Some(spec) = pod.spec.as_ref() else {
        return false;
    };
    spec.host_network.unwrap_or_default()
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
