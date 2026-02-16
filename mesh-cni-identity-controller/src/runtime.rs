use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::core::v1::{Namespace, Node, Pod};
use kube::{
    Api, Client, ResourceExt,
    runtime::{Controller, reflector::ObjectRef},
};
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
        (identity_store, identity_subscriber),
        (pod_store, pod_subscriber),
        (namespace_store, namespace_subscriber),
        (node_store, node_subscriber),
    ) = store_init;

    let mapper_namespace_pod_store = pod_store.clone();
    let mapper_identity_pod_store = pod_store.clone();
    let mapper_identity_namespace_store = namespace_store.clone();

    let context = Arc::new(Context {
        node_name,
        identity_store: identity_store.clone(),
        namespace_store,
        bpf_maps,
    });

    let namespace_mapper = move |namespace: Arc<Namespace>| -> Vec<ObjectRef<Pod>> {
        let ns = namespace.name_any();
        mapper_namespace_pod_store
            .state()
            .iter()
            .filter_map(|pod| {
                if pod.namespace().as_deref() == Some(ns.as_str()) {
                    Some(ObjectRef::new(&pod.name_any()).within(&ns))
                } else {
                    None
                }
            })
            .collect()
    };

    let identity_mapper = move |identity: Arc<Identity>| -> Vec<ObjectRef<Pod>> {
        let Some(identity_ns) = identity.namespace() else {
            return Vec::new();
        };
        let Some(namespace) = mapper_identity_namespace_store.get(&ObjectRef::new(&identity_ns))
        else {
            return Vec::new();
        };

        mapper_identity_pod_store
            .state()
            .iter()
            .filter_map(|pod| {
                if pod.namespace().as_deref() != Some(identity_ns.as_str()) {
                    return None;
                }
                if identity.pod_namespace_labels_match(pod, &namespace) {
                    Some(ObjectRef::new(&pod.name_any()).within(&identity_ns))
                } else {
                    None
                }
            })
            .collect()
    };

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
        .watches_shared_stream(namespace_subscriber, namespace_mapper)
        .watches_shared_stream(identity_subscriber, identity_mapper)
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
