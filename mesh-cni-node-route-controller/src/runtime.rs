use std::{sync::Arc, time::Duration};

use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::Node;
use kube::{
    Api, Client,
    runtime::{Config, Controller},
};
use mesh_cni_k8s_utils::create_store_and_touched_subscriber;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Result,
    context::Context,
    controller::{error_policy, reconcile, reconcile_all_node_routes},
};

const MESH_VXLAN_IFACE: &str = "mesh_vxlan0";

pub async fn start_node_route_controller(
    kube_client: Client,
    node_name: String,
    cancel: CancellationToken,
) -> Result<()> {
    let node_api: Api<Node> = Api::all(kube_client);
    let (node_store, node_subscriber) =
        create_store_and_touched_subscriber(node_api, Some(Duration::from_secs(30))).await?;

    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);
    let mesh_vxlan_ifindex = link_index(&handle, MESH_VXLAN_IFACE).await?;
    let context = Arc::new(Context {
        node_name,
        node_store: node_store.clone(),
        handle,
        mesh_vxlan_ifindex,
    });

    reconcile_all_node_routes(&context).await?;

    let config = Config::default().concurrency(5);

    info!("Starting node route controller");
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

// TODO: move generic-ish netlink related funcs to shared crate
async fn link_index(handle: &rtnetlink::Handle, name: &str) -> Result<u32> {
    let link = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute()
        .try_next()
        .await?
        .ok_or_else(|| crate::Error::MissingPrecondition(format!("missing interface {name}")))?;

    Ok(link.header.index)
}
