use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_openapi::api::core::v1::Node;
use kube::{
    Api, Client,
    runtime::{Config, Controller},
};
use mesh_cni_k8s_utils::create_store_and_touched_subscriber;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Result, VxlanRemoteCidrsDataplane,
    context::Context,
    controller::{error_policy, reconcile, reconcile_all_vxlan_remote_cidrs},
};

pub async fn start_vxlan_controller<R>(
    kube_client: Client,
    node_name: String,
    routes: R,
    vxlan_ifindex: u32,

    cancel: CancellationToken,
) -> Result<()>
where
    R: VxlanRemoteCidrsDataplane,
{
    let node_api: Api<Node> = Api::all(kube_client);
    let (node_store, node_subscriber) = create_store_and_touched_subscriber(
        node_api,
        kube::runtime::watcher::Config::default(),
        Some(Duration::from_secs(30)),
    )
    .await?;

    let context = Arc::new(Context {
        node_name,
        node_store: node_store.clone(),
        routes,
        vxlan_ifindex,
    });

    reconcile_all_vxlan_remote_cidrs(&context)?;

    let config = Config::default().concurrency(5);

    info!("Starting vxlan controller");
    Controller::for_shared_stream(node_subscriber, node_store)
        .with_config(config)
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
