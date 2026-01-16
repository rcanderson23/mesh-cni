use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_openapi::api::core::v1::{Namespace, Pod};
use kube::{
    Api, Client, ResourceExt,
    runtime::{Config, Controller, reflector::ObjectRef},
};
use mesh_cni_k8s_utils::create_store_and_subscriber;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::{
    Error, Result,
    context::Context,
    controller::{error_policy, reconcile_namespace},
};

pub async fn start_identity_controllers(client: Client, cancel: CancellationToken) -> Result<()> {
    let store_init = timeout(Duration::from_secs(30), async {
        tokio::try_join!(
            create_store_and_subscriber(Api::all(client.clone()), Some(Duration::from_secs(30))),
            create_store_and_subscriber(Api::all(client.clone()), Some(Duration::from_secs(30))),
            create_store_and_subscriber(Api::all(client.clone()), Some(Duration::from_secs(30))),
        )
    })
    .await
    .map_err(|_| Error::Timeout)??;

    let ((pods, pod_subscriber), (namespaces, namespace_subscriber), (identities, _)) = store_init;
    let context = Arc::new(Context {
        client,
        pods: pods.clone(),
        identities,
    });

    let config = Config::default();
    let config = config.debounce(Duration::from_secs(2));
    let config = config.concurrency(10);
    Controller::for_shared_stream(namespace_subscriber, namespaces)
        .watches_shared_stream(pod_subscriber, ns_mapper)
        .graceful_shutdown_on(shutdown(cancel))
        .with_config(config)
        .run(reconcile_namespace, error_policy, context)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
    Ok(())
}

async fn shutdown(cancel: CancellationToken) {
    cancel.cancelled().await;
}

fn ns_mapper(pod: Arc<Pod>) -> Option<ObjectRef<Namespace>> {
    let ns = pod.namespace()?;
    Some(ObjectRef::new(&ns))
}
