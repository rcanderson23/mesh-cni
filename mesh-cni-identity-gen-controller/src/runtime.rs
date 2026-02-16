use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_openapi::api::{
    core::v1::{Namespace, Pod},
    networking::v1::NetworkPolicy,
};
use kube::{
    Api, Client, ResourceExt,
    runtime::{Config, Controller, reflector::ObjectRef},
};
use mesh_cni_crds::v1alpha1::{cidridentity::CIDRIdentity, identity::Identity};
use mesh_cni_k8s_utils::{create_store_and_subscriber, create_store_and_touched_subscriber};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::{
    Error, Result,
    context::Context,
    controller::error_policy,
    namespace::reconcile_namespace,
    networkpolicy::{reconcile_cidr_identities, reconcile_network_policy},
};

pub async fn start_identity_gen_controller(
    client: Client,
    cancel: CancellationToken,
) -> Result<()> {
    let store_init = timeout(Duration::from_secs(30), async {
        tokio::try_join!(
            create_store_and_subscriber(
                Api::<Pod>::all(client.clone()),
                Some(Duration::from_secs(30))
            ),
            create_store_and_subscriber(
                Api::<Namespace>::all(client.clone()),
                Some(Duration::from_secs(30))
            ),
            create_store_and_subscriber(
                Api::<Identity>::all(client.clone()),
                Some(Duration::from_secs(30))
            ),
            create_store_and_touched_subscriber(
                Api::<NetworkPolicy>::all(client.clone()),
                Some(Duration::from_secs(30))
            ),
            create_store_and_subscriber(
                Api::<CIDRIdentity>::all(client.clone()),
                Some(Duration::from_secs(30))
            ),
        )
    })
    .await
    .map_err(|_| Error::Timeout)??;

    let (
        (pods, pod_subscriber),
        (namespaces, namespace_subscriber),
        (identities, identity_subscriber),
        (network_policies, network_policy_subscriber),
        (cidr_identities, _),
    ) = store_init;
    let context = Arc::new(Context {
        client: client.clone(),
        pods: pods.clone(),
        identities,
        network_policies: network_policies.clone(),
        cidr_identities,
    });

    reconcile_cidr_identities(&context).await?;

    let config = Config::default().debounce(Duration::from_millis(200));
    let pod_config = config.clone().concurrency(10);

    // CIDRIdentity is generated globally so concurrency should stay 1 here
    let network_policy_config = config.clone().concurrency(1);

    let network_policy_controller =
        Controller::for_shared_stream(network_policy_subscriber, network_policies)
            .graceful_shutdown_on(shutdown(cancel.clone()))
            .with_config(network_policy_config)
            .run(reconcile_network_policy, error_policy, context.clone())
            .filter_map(|x| async move { std::result::Result::ok(x) })
            .for_each(|_| futures::future::ready(()));

    let namespace_controller = Controller::for_shared_stream(namespace_subscriber, namespaces)
        .watches_shared_stream(pod_subscriber, ns_mapper)
        .watches_shared_stream(identity_subscriber, ns_mapper)
        .graceful_shutdown_on(shutdown(cancel))
        .with_config(pod_config)
        .run(reconcile_namespace, error_policy, context)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()));

    tokio::join!(network_policy_controller, namespace_controller);
    Ok(())
}

async fn shutdown(cancel: CancellationToken) {
    cancel.cancelled().await;
}

fn ns_mapper<K: ResourceExt>(k: Arc<K>) -> Option<ObjectRef<Namespace>> {
    let ns = k.namespace()?;
    Some(ObjectRef::new(&ns))
}
