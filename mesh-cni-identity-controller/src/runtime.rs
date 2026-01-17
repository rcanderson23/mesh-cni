use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::core::v1::{Namespace, Node, Pod};
use kube::{Api, Client, runtime::Controller};
use mesh_cni_crds::v1alpha1::identity::Identity;
use mesh_cni_k8s_utils::create_store_and_subscriber;
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;

use crate::{
    IdentityBpfState, Result,
    context::Context,
    controller::{error_policy, reconcile},
};

pub async fn start_identity_controllers<B>(
    client: Client,
    node_name: String,
    cancel: CancellationToken,
    bpf_maps: B,
) -> Result<()>
where
    B: IdentityBpfState + Send + Sync + 'static,
{
    let store_init = tokio::try_join!(
        create_store_and_subscriber(
            Api::<Identity>::all(client.clone()),
            Some(Duration::from_secs(30))
        ),
        create_store_and_subscriber(
            Api::<Pod>::all(client.clone()),
            Some(Duration::from_secs(30))
        ),
        create_store_and_subscriber(
            Api::<Namespace>::all(client.clone()),
            Some(Duration::from_secs(30))
        ),
        create_store_and_subscriber(
            Api::<Node>::all(client.clone()),
            Some(Duration::from_secs(30))
        ),
    )?;

    let (
        (identity_store, _),
        (pod_store, pod_subscriber),
        (namespace_store, _),
        (node_store, node_subscriber),
    ) = store_init;

    let context = Arc::new(Context {
        node_name,
        identity_store,
        namespace_store,
        bpf_maps,
    });

    // TODO: This process may be better served in the pod creation path if we can get relevant pod
    // information (IPs, labels) on creation
    tokio::spawn(
        Controller::for_shared_stream(node_subscriber, node_store)
            .graceful_shutdown_on(shutdown(cancel.clone()))
            .run(reconcile, error_policy, context.clone())
            .filter_map(|x| async move { std::result::Result::ok(x) })
            .for_each(|_| futures::future::ready(())),
    );
    Controller::for_shared_stream(pod_subscriber, pod_store)
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
