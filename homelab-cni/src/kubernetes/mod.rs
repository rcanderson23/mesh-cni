use futures::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::serde::de::DeserializeOwned;
use kube::runtime::reflector::ReflectHandle;
use kube::runtime::{WatchStreamExt, reflector, watcher};
use kube::{Api, Resource, ResourceExt};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::net::IpAddr;
use std::str::FromStr;
use tracing::{error, trace};

use crate::{Error, Result};

pub struct KubeState {
    pub pod_subscriber: ReflectHandle<Pod>,
    pub network_policy_subscriber: ReflectHandle<NetworkPolicy>,
}

pub async fn start_kube_watchers() -> Result<KubeState> {
    install_crypto()?;
    let client = kube::Client::try_default().await?;
    let pod: Api<Pod> = Api::all(client.clone());
    let netpol: Api<NetworkPolicy> = Api::all(client);

    let pod_subscriber = create_subscriber(pod).await?;
    let network_policy_subscriber = create_subscriber(netpol).await?;

    Ok(KubeState {
        pod_subscriber,
        network_policy_subscriber,
    })
}

fn install_crypto() -> Result<()> {
    let crypto_provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();
    crypto_provider
        .install_default()
        .map_err(|_| Error::CryptoError("failed to install crypto provider".into()))
}

async fn create_subscriber<K>(api: Api<K>) -> Result<ReflectHandle<K>>
where
    K: Resource + Send + Clone + Debug + DeserializeOwned + Sync + 'static,
    <K as Resource>::DynamicType: Default + Eq + Send + DeserializeOwned + Hash + Clone,
{
    let (store, writer) = reflector::store_shared(1000);
    let subscriber = writer
        .subscribe()
        .ok_or_else(|| Error::StoreCreation("failed to create subscriber".into()))?;
    let stream = watcher(api, watcher::Config::default())
        .default_backoff()
        .reflect(writer)
        .applied_objects()
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

#[derive(Clone)]
pub struct IpIdentity {
    pub namespace: String,
    pub labels: BTreeMap<String, String>,
    pub ips: Vec<IpAddr>,
}

impl TryFrom<&Pod> for IpIdentity {
    type Error = Error;

    fn try_from(pod: &Pod) -> std::result::Result<Self, Self::Error> {
        if let Some(status) = pod.status.as_ref() {
            if let Some(ips) = status.pod_ips.as_ref() {
                let ips = ips
                    .iter()
                    .map(|ip| IpAddr::from_str(&ip.ip))
                    .filter_map(|ip| ip.ok())
                    .collect();
                return Ok(Self {
                    namespace: pod.namespace().ok_or_else(|| Error::ConvertPodIpIdentity)?,
                    labels: pod.labels().to_owned(),
                    ips,
                });
            }
        }
        Err(Error::ConvertPodIpIdentity)
    }
}

fn _pod_matches_node_name(pod: &Pod, node_name: &str) -> bool {
    let Some(spec) = pod.spec.as_ref() else {
        return false;
    };
    let Some(name) = spec.node_name.as_ref() else {
        return false;
    };
    name == node_name
}
