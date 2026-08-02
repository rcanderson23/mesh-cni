use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_openapi::api::core::v1::{Namespace, Pod};
use kube::{
    Api, Client, ResourceExt,
    api::DeleteParams,
    runtime::{Controller, reflector::ObjectRef},
};
use mesh_cni_crds::v1alpha1::meshidentityslice::MeshIdentitySlice;
use mesh_cni_k8s_utils::create_store_and_touched_subscriber;
use tokio::{task::JoinHandle, time::timeout};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{
    Error, Result,
    context::Context,
    controller::{LABEL_CLUSTER_OWNER, error_policy, reconcile},
};

const ORPHAN_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

pub async fn start_meshidentityslice_gen_controller(
    local_client: Client,
    source_client: Client,
    cluster_name: String,
    cancel: CancellationToken,
) -> Result<JoinHandle<()>> {
    let store_init = timeout(Duration::from_secs(30), async {
        tokio::try_join!(
            create_store_and_touched_subscriber(
                Api::<Pod>::all(source_client.clone()),
                kube::runtime::watcher::Config::default(),
                Some(Duration::from_secs(30))
            ),
            create_store_and_touched_subscriber(
                Api::<Namespace>::all(source_client.clone()),
                kube::runtime::watcher::Config::default(),
                Some(Duration::from_secs(30))
            ),
            create_store_and_touched_subscriber(
                Api::<Namespace>::all(local_client.clone()),
                kube::runtime::watcher::Config::default(),
                Some(Duration::from_secs(30))
            ),
            create_store_and_touched_subscriber(
                Api::<MeshIdentitySlice>::all(local_client.clone()),
                kube::runtime::watcher::Config::default(),
                Some(Duration::from_secs(30))
            ),
        )
    })
    .await
    .map_err(|_| Error::Timeout)??;

    let (
        (pods, pod_subscriber),
        (namespaces, namespace_subscriber),
        (local_namespaces, local_namespace_subscriber),
        (meshidentityslices, meshidentityslice_subscriber),
    ) = store_init;
    let context = Arc::new(Context {
        client: local_client,
        pods,
        source_namespaces: namespaces.clone(),
        local_namespaces,
        meshidentityslices,
        cluster_name,
    });

    let controller_config = kube::runtime::Config::default().concurrency(10);
    info!("starting meshidentity-gen-controller");
    let h = tokio::spawn(async move {
        let controller = Controller::for_shared_stream(namespace_subscriber, namespaces)
            .watches_shared_stream(pod_subscriber, ns_mapper)
            .watches_shared_stream(local_namespace_subscriber, local_ns_mapper)
            .watches_shared_stream(meshidentityslice_subscriber, ns_mapper)
            .graceful_shutdown_on(shutdown(cancel.clone()))
            .with_config(controller_config)
            .run(reconcile, error_policy, context.clone())
            .filter_map(|x| async move { std::result::Result::ok(x) })
            .for_each(|_| futures::future::ready(()));

        tokio::join!(
            controller,
            start_orphan_meshidentityslice_cleanup(context, cancel),
        );
    });
    Ok(h)
}

fn ns_mapper<K: ResourceExt>(k: Arc<K>) -> Option<ObjectRef<Namespace>> {
    let namespace = k.namespace()?;
    Some(ObjectRef::new(&namespace))
}

fn local_ns_mapper(namespace: Arc<Namespace>) -> Option<ObjectRef<Namespace>> {
    Some(ObjectRef::new(&namespace.name_any()))
}

pub(crate) async fn shutdown(cancel: CancellationToken) {
    tokio::select! {
        _ = cancel.cancelled() => {}
    }
}

async fn start_orphan_meshidentityslice_cleanup(ctx: Arc<Context>, cancel: CancellationToken) {
    let mut interval = tokio::time::interval(ORPHAN_SWEEP_INTERVAL);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = interval.tick() => {
                if let Err(e) = cleanup_orphan_meshidentityslices(&ctx).await {
                    error!(error = %e, "failed orphan MeshIdentitySlice sweep");
                }
            }
        }
    }
}

async fn cleanup_orphan_meshidentityslices(ctx: &Arc<Context>) -> Result<()> {
    let dp = DeleteParams::default();

    for slice in ctx.meshidentityslices.state() {
        if slice.metadata.deletion_timestamp.is_some() {
            continue;
        }
        if slice.labels().get(LABEL_CLUSTER_OWNER) != Some(&ctx.cluster_name) {
            continue;
        }
        let Some(namespace) = slice.namespace() else {
            continue;
        };
        if ctx
            .source_namespaces
            .get(&ObjectRef::new(&namespace))
            .is_some()
        {
            continue;
        }
        info!(
            namespace = %namespace,
            name = %slice.name_any(),
            cluster = %ctx.cluster_name,
            "deleting orphan MeshIdentitySlice for missing source namespace"
        );
        let meshidentityslices: Api<MeshIdentitySlice> =
            Api::namespaced(ctx.client.clone(), &namespace);
        meshidentityslices.delete(&slice.name_any(), &dp).await?;
    }
    Ok(())
}
