use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use kube::{Api, Client};
use mesh_cni_crds::v1alpha1::cluster::Cluster;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

pub struct Context {
    pub client: Client,
    pub cluster_api: Api<Cluster>,
    /// Stores cancellation tokens for shutting down child controllers
    /// when the cluster is deleted
    pub controllers: Arc<Mutex<BTreeMap<String, ClusterCancellation>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownState {
    Running,
    Completed,
}

#[derive(Debug, Clone)]
pub struct ClusterCancellation {
    cancel: CancellationToken,
    shutdown: watch::Receiver<ShutdownState>,
}

#[derive(Debug, Clone)]
pub struct ClusterCancellationHandle {
    cancel: CancellationToken,
    shutdown: watch::Sender<ShutdownState>,
}

impl ClusterCancellation {
    pub fn new() -> (Self, ClusterCancellationHandle) {
        let cancel = CancellationToken::new();
        let (shutdown, shutdown_rx) = watch::channel(ShutdownState::Running);
        let cancellation = Self {
            cancel: cancel.clone(),
            shutdown: shutdown_rx,
        };
        let handle = ClusterCancellationHandle { cancel, shutdown };
        (cancellation, handle)
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn request_shutdown(&self) {
        self.cancel.cancel();
    }

    pub fn is_shutdown_complete(&self) -> bool {
        matches!(*self.shutdown.borrow(), ShutdownState::Completed)
    }
}

impl ClusterCancellationHandle {
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn mark_shutdown_complete(&self) {
        let _ = self.shutdown.send(ShutdownState::Completed);
    }
}
