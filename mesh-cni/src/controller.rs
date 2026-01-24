use mesh_cni_identity_gen_controller::start_identity_gen_controller;
use tokio_util::sync::CancellationToken;

use crate::{Result, config::ControllerArgs};

pub async fn start(
    _args: ControllerArgs,
    ready: CancellationToken,
    cancel: CancellationToken,
) -> Result<()> {
    let client = kube::Client::try_default().await?;

    // let service_controller =
    //     start_service_controller(local_client.clone(), endpoint_slice_state, cancel.clone());
    //
    // let service_handle = tokio::spawn(service_controller);

    let identity_controller = start_identity_gen_controller(client, cancel.clone());

    let identity_handle = tokio::spawn(identity_controller);

    ready.cancel();
    tokio::select! {
        _ = cancel.cancelled() => {},
        _ = identity_handle => {}
    }

    Ok(())
}
