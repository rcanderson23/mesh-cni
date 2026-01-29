use std::sync::Arc;

use futures::StreamExt;
use kube::{Api, Client, runtime::Controller};
use mesh_cni_k8s_utils::create_store_and_subscriber;
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

use crate::{
    Error, PolicyControllerBpf, Result,
    context::Context,
    controller::{error_policy, reconcile},
};

pub async fn start_policy_controllers<P>(
    client: Client,
    policy_bpf_state: P,
    cancel: CancellationToken,
) -> Result<()>
where
    P: PolicyControllerBpf + Send + Sync + 'static,
{
    let store_init = timeout(Duration::from_secs(30), async {
        tokio::try_join!(
            create_store_and_subscriber(Api::all(client.clone()), Some(Duration::from_secs(30))),
            create_store_and_subscriber(Api::all(client.clone()), Some(Duration::from_secs(30))),
            create_store_and_subscriber(Api::all(client.clone()), Some(Duration::from_secs(30))),
            create_store_and_subscriber(Api::all(client.clone()), Some(Duration::from_secs(30))),
        )
    })
    .await
    .map_err(|_| Error::Timeout("store initialization".into()))??;

    let (
        (pod_store, _pod_subscriber),
        (policy_store, _policy_subscriber),
        (namespace_store, _namespace_subscriber),
        (identity_store, identity_subscriber),
    ) = store_init;

    let context = Arc::new(Context {
        pod_store: pod_store.clone(),
        policy_store: policy_store.clone(),
        namespace_store: namespace_store.clone(),
        identity_store: identity_store.clone(),
        policy_bpf_state,
    });

    tokio::spawn(
        Controller::for_shared_stream(identity_subscriber, identity_store)
            .graceful_shutdown_on(shutdown(cancel))
            .run(reconcile, error_policy, context)
            .filter_map(|x| async move { std::result::Result::ok(x) })
            .for_each(|_| futures::future::ready(())),
    );

    Ok(())
}

async fn shutdown(cancel: CancellationToken) {
    cancel.cancelled().await;
}
