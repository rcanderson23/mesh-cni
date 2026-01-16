use std::sync::Arc;

use futures::StreamExt;
use kube::{Api, Client, runtime::Controller};
use mesh_cni_k8s_utils::create_store_and_subscriber;
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

use crate::{
    Error, Result,
    context::Context,
    controller::{error_policy, reconcile_namespace, reconcile_pod, reconcile_policy},
};

pub async fn start_policy_controllers<NPA>(
    client: Client,
    cancel: CancellationToken,
) -> Result<()> {
    let store_init = timeout(Duration::from_secs(30), async {
        tokio::try_join!(
            create_store_and_subscriber(Api::all(client.clone()), Some(Duration::from_secs(30))),
            create_store_and_subscriber(Api::all(client.clone()), Some(Duration::from_secs(30))),
            create_store_and_subscriber(Api::all(client.clone()), Some(Duration::from_secs(30))),
        )
    })
    .await
    .map_err(|_| Error::Timeout("store initialization".into()))??;

    let (
        (pod_store, pod_subscriber),
        (policy_store, policy_subscriber),
        (namespace_store, namespace_subscriber),
    ) = store_init;

    let context = Arc::new(Context {
        pod_store: pod_store.clone(),
        policy_store: policy_store.clone(),
        namespace_store: namespace_store.clone(),
    });

    tokio::spawn(
        Controller::for_shared_stream(namespace_subscriber, namespace_store)
            .graceful_shutdown_on(shutdown(cancel.clone()))
            .run(reconcile_namespace, error_policy, context.clone())
            .filter_map(|x| async move { std::result::Result::ok(x) })
            .for_each(|_| futures::future::ready(())),
    );

    tokio::spawn(
        Controller::for_shared_stream(policy_subscriber, policy_store)
            .graceful_shutdown_on(shutdown(cancel.clone()))
            .run(reconcile_policy, error_policy, context.clone())
            .filter_map(|x| async move { std::result::Result::ok(x) })
            .for_each(|_| futures::future::ready(())),
    );

    tokio::spawn(
        Controller::for_shared_stream(pod_subscriber, pod_store)
            .graceful_shutdown_on(shutdown(cancel))
            .run(reconcile_pod, error_policy, context)
            .filter_map(|x| async move { std::result::Result::ok(x) })
            .for_each(|_| futures::future::ready(())),
    );

    Ok(())
}

async fn shutdown(cancel: CancellationToken) {
    cancel.cancelled().await;
}
