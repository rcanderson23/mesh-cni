use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::core::v1::{Namespace, Pod};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::{Api, Client, runtime::Controller};
use tokio_util::sync::CancellationToken;

use mesh_cni_k8s_utils::create_store_and_subscriber;

use crate::Result;
use crate::context::{Context, NetworkPolicyAnalyzer};
use crate::controller::{error_policy, reconcile_namespace, reconcile_pod, reconcile_policy};

pub async fn start_policy_controllers<NPA>(
    client: Client,
    analyzer: NPA,
    cancel: CancellationToken,
) -> Result<()>
where
    NPA: NetworkPolicyAnalyzer + Send + Sync + 'static,
{
    let (pod_store, pod_subscriber) =
        create_store_and_subscriber(Api::<Pod>::all(client.clone())).await?;
    let (policy_store, policy_subscriber) =
        create_store_and_subscriber(Api::<NetworkPolicy>::all(client.clone())).await?;
    let (namespace_store, namespace_subscriber) =
        create_store_and_subscriber(Api::<Namespace>::all(client.clone())).await?;

    let context = Arc::new(Context {
        analyzer,
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
