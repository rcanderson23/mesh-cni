use std::{
    fmt::Debug,
    hash::Hash,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_broadcast::Receiver as AsyncBroadcastReceiver;
use futures::{Stream, StreamExt};
use k8s_openapi::serde::de::DeserializeOwned;
use kube::{
    Api, Resource,
    runtime::{
        WatchStreamExt, reflector,
        reflector::{ReflectHandle, Store},
        watcher,
    },
};
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

pub struct TouchedSubscriber<K>
where
    K: Resource + Clone + 'static,
    K::DynamicType: Eq + Hash + Clone,
{
    reflect_handle: ReflectHandle<K>,
    delete_rx: AsyncBroadcastReceiver<Arc<K>>,
    poll_delete_first: bool,
    reflect_done: bool,
    delete_done: bool,
}

impl<K> Clone for TouchedSubscriber<K>
where
    K: Resource + Clone + Send + Sync + 'static,
    K::DynamicType: Default + Eq + Send + DeserializeOwned + Hash + Clone,
{
    fn clone(&self) -> Self {
        Self {
            reflect_handle: self.reflect_handle.clone(),
            delete_rx: self.delete_rx.clone(),
            poll_delete_first: self.poll_delete_first,
            reflect_done: false,
            delete_done: false,
        }
    }
}

impl<K> futures::Stream for TouchedSubscriber<K>
where
    K: Resource + Clone + Send + Sync + 'static,
    K::DynamicType: Default + Eq + Send + DeserializeOwned + Hash + Clone,
{
    type Item = Arc<K>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let delete_first = this.poll_delete_first;
        this.poll_delete_first = !this.poll_delete_first;

        let first = if delete_first {
            this.poll_delete(cx)
        } else {
            this.poll_reflect(cx)
        };
        let second = if delete_first {
            this.poll_reflect(cx)
        } else {
            this.poll_delete(cx)
        };

        if let Poll::Ready(Some(item)) = first {
            return Poll::Ready(Some(item));
        }
        if let Poll::Ready(Some(item)) = second {
            return Poll::Ready(Some(item));
        }
        if this.reflect_done && this.delete_done {
            return Poll::Ready(None);
        }

        Poll::Pending
    }
}

impl<K> TouchedSubscriber<K>
where
    K: Resource + Clone + Send + Sync + 'static,
    K::DynamicType: Default + Eq + Send + DeserializeOwned + Hash + Clone,
{
    fn new(reflect_handle: ReflectHandle<K>, delete_rx: AsyncBroadcastReceiver<Arc<K>>) -> Self {
        Self {
            reflect_handle,
            delete_rx,
            poll_delete_first: false,
            reflect_done: false,
            delete_done: false,
        }
    }

    fn poll_reflect(&mut self, cx: &mut Context<'_>) -> Poll<Option<Arc<K>>> {
        if self.reflect_done {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.reflect_handle).poll_next(cx) {
            Poll::Ready(Some(item)) => Poll::Ready(Some(item)),
            Poll::Ready(None) => {
                self.reflect_done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_delete(&mut self, cx: &mut Context<'_>) -> Poll<Option<Arc<K>>> {
        if self.delete_done {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.delete_rx).poll_next(cx) {
            Poll::Ready(Some(item)) => Poll::Ready(Some(item)),
            Poll::Ready(None) => {
                self.delete_done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// Builds a reflected Store and a touched-object trigger stream from the same watch pipeline.
pub async fn create_store_and_touched_subscriber<K>(
    api: Api<K>,
    timeout: Option<Duration>,
) -> Result<(Store<K>, TouchedSubscriber<K>)>
where
    K: Resource + Send + Clone + Debug + DeserializeOwned + Sync + 'static,
    <K as Resource>::DynamicType: Default + Eq + Send + DeserializeOwned + Hash + Clone,
{
    let size = 1000;
    let (store, writer) = reflector::store_shared(size);
    let subscriber: ReflectHandle<K> = writer
        .subscribe()
        .ok_or_else(|| Error::StoreCreation("failed to create subscriber".into()))?;
    let (mut delete_tx, delete_rx) = async_broadcast::broadcast::<Arc<K>>(size);
    delete_tx.set_await_active(false);
    let stream_delete_tx = delete_tx.clone();

    let stream = watcher(api, watcher::Config::default())
        .default_backoff()
        .reflect_shared(writer)
        .for_each(move |res| {
            let delete_tx = stream_delete_tx.clone();
            async move {
                match res {
                    Ok(watcher::Event::Delete(obj)) => {
                        if let Err(e) = delete_tx.broadcast_direct(Arc::new(obj)).await {
                            trace!(%e, "delete subscriber dropped");
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        error!(%e, "unexpected error with touched stream")
                    }
                }
            }
        });

    tokio::spawn(stream);
    let wait = store.wait_until_ready();
    if let Some(timeout) = timeout {
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| Error::StoreCreation("timed out waiting for store".into()))?
            .map_err(|e| Error::StoreCreation(e.to_string()))?;
    } else {
        wait.await
            .map_err(|e| Error::StoreCreation(e.to_string()))?;
    }
    Ok((store, TouchedSubscriber::new(subscriber, delete_rx)))
}

pub async fn create_store_and_subscriber<K>(
    api: Api<K>,
    timeout: Option<Duration>,
) -> Result<(Store<K>, ReflectHandle<K>)>
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
    let wait = store.wait_until_ready();
    if let Some(timeout) = timeout {
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| Error::StoreCreation("timed out waiting for store".into()))?
            .map_err(|e| Error::StoreCreation(e.to_string()))?;
    } else {
        wait.await
            .map_err(|e| Error::StoreCreation(e.to_string()))?;
    }
    Ok((store, subscriber))
}

pub fn sanitize_pod_labels(labels: &mut std::collections::BTreeMap<String, String>) {
    let removal_list = [
        "controller-revision-hash",
        "pod-template-hash",
        "pod-template-generation",
    ];

    removal_list.iter().for_each(|i| {
        labels.remove(*i);
    });
}
