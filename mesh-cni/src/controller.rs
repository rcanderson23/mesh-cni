use mesh_cni_cluster_controller::start_cluster_controller;
use mesh_cni_identity_gen_controller::start_identity_gen_controller;
use mesh_cni_meshendpoint_gen_controller::start_meshendpoint_gen_controller;
use tokio_util::sync::CancellationToken;

use crate::{Result, config::ControllerArgs};

pub async fn start(
    args: ControllerArgs,
    ready: CancellationToken,
    cancel: CancellationToken,
) -> Result<()> {
    let client = kube::Client::try_default().await?;

    let identity_controller = start_identity_gen_controller(client.clone(), cancel.child_token());

    let identity_handle = tokio::spawn(identity_controller);

    // Start the local mesh gen controller. Other clusters' mesh_endpoint_gen_controllers are
    // spawned when Cluster custom resources are created
    let mesh_endpoint_gen_handle = start_meshendpoint_gen_controller(
        client.clone(),
        client.clone(),
        "local".to_string(),
        cancel.child_token(),
    )
    .await?;

    let cluster_controller = start_cluster_controller(client, args.namespace, cancel.child_token());
    let cluster_handle = tokio::spawn(cluster_controller);

    ready.cancel();
    tokio::select! {
        _ = cancel.cancelled() => {},
        _ = identity_handle => {},
        _ = mesh_endpoint_gen_handle => {},
        _ = cluster_handle => {},
    }

    Ok(())
}
