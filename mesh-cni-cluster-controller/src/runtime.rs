use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use futures::StreamExt;
use kube::{
    Api, Client,
    runtime::{Controller, watcher::Config},
};
use mesh_cni_crds::v1alpha1::cluster::Cluster;
use tokio_util::sync::CancellationToken;

use crate::{
    Result,
    context::Context,
    controller::{error_policy, reconcile},
};

pub async fn start_cluster_controller(client: Client, cancel: CancellationToken) -> Result<()> {
    let api: Api<Cluster> = Api::all(client.clone());
    let context = Arc::new(Context {
        client,
        cluster_api: api.clone(),
        controllers: Arc::new(Mutex::new(BTreeMap::default())),
    });

    Controller::new(api, Config::default().any_semantic())
        .graceful_shutdown_on(shutdown(cancel))
        .run(reconcile, error_policy, context)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
    Ok(())
}

async fn shutdown(cancel: CancellationToken) {
    cancel.cancelled().await;
}
