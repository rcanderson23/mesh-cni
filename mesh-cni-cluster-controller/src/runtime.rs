use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    Api, Client,
    runtime::{self, Controller, watcher::Config},
};
use mesh_cni_crds::v1alpha1::cluster::Cluster;
use mesh_cni_k8s_utils::create_store_and_touched_subscriber;
use tokio_util::sync::CancellationToken;

use crate::{
    Result,
    context::Context,
    controller::{error_policy, reconcile},
};

pub async fn start_cluster_controller(
    client: Client,
    namespace: String,
    cancel: CancellationToken,
) -> Result<()> {
    let (secrets, _) = create_store_and_touched_subscriber(
        Api::<Secret>::namespaced(client.clone(), &namespace),
        Some(Duration::from_secs(30)),
    )
    .await?;
    let cluster: Api<Cluster> = Api::all(client.clone());
    let context = Arc::new(Context {
        client,
        namespace,
        secrets,
        controllers: RwLock::new(BTreeMap::default()),
    });

    let controller_config = runtime::Config::default().concurrency(5);
    Controller::new(cluster, Config::default().any_semantic())
        .graceful_shutdown_on(shutdown(cancel))
        .with_config(controller_config)
        .run(reconcile, error_policy, context)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
    Ok(())
}

async fn shutdown(cancel: CancellationToken) {
    cancel.cancelled().await;
}
