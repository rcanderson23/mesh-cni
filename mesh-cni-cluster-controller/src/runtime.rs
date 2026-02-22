use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    Api, Client, ResourceExt,
    runtime::{
        self, Controller,
        reflector::{ObjectRef, Store},
    },
};
use mesh_cni_crds::v1alpha1::cluster::Cluster;
use mesh_cni_k8s_utils::create_store_and_touched_subscriber;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::{
    Error, Result,
    context::Context,
    controller::{error_policy, reconcile},
};

pub async fn start_cluster_controller(
    client: Client,
    namespace: String,
    cancel: CancellationToken,
) -> Result<()> {
    let store_init = timeout(Duration::from_secs(30), async {
        tokio::try_join!(
            create_store_and_touched_subscriber(
                Api::<Secret>::namespaced(client.clone(), &namespace),
                Some(Duration::from_secs(30))
            ),
            create_store_and_touched_subscriber(
                Api::<Cluster>::all(client.clone()),
                Some(Duration::from_secs(30))
            ),
        )
    })
    .await
    .map_err(|_| Error::Timeout)??;

    let ((secrets, secret_subscriber), (clusters, cluster_subscriber)) = store_init;
    let context = Arc::new(Context {
        client,
        namespace,
        secrets,
        controllers: RwLock::new(BTreeMap::default()),
    });

    let cluster_mapper: Store<Cluster> = clusters.clone();
    let secret_mapper = move |secret: Arc<Secret>| -> Option<ObjectRef<Cluster>> {
        cluster_mapper.state().iter().find_map(|c| {
            if c.spec.secret.name == secret.name_any() {
                Some(ObjectRef::new(&c.name_any()))
            } else {
                None
            }
        })
    };
    let controller_config = runtime::Config::default().concurrency(5);
    Controller::for_shared_stream(cluster_subscriber, clusters)
        .watches_shared_stream(secret_subscriber, secret_mapper)
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
