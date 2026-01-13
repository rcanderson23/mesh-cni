use k8s_openapi::api::discovery::v1::EndpointSlice;
use mesh_cni_identity::start_identity_controllers;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::config::ControllerArgs;
use crate::kubernetes::cluster::{Cluster, ClusterConfigs};
use crate::kubernetes::controllers::service::start_service_controller;
use crate::kubernetes::state::MultiClusterState;
use crate::{Error, Result, kubernetes};

pub async fn start(
    args: ControllerArgs,
    ready: CancellationToken,
    cancel: CancellationToken,
) -> Result<()> {
    let configs = ClusterConfigs::try_new_configs(args.mesh_clusters_config).await?;
    let mut local_cluster = Cluster::try_new(configs.local).await?;
    // for config in configs.remote {
    //     match Cluster::try_new(config).await {
    //         Ok(cluster) => clusters.push(cluster),
    //         Err(e) => {
    //             warn!(%e, "failed to create cluster from config");
    //             continue;
    //         }
    //     };
    // }
    // clusters.push(local_cluster.clone());
    //
    // let endpoint_slice_state: MultiClusterState<EndpointSlice> =
    //     kubernetes::state::MultiClusterState::try_new(clusters).await?;
    //
    // let endpoint_slice_state = endpoint_slice_state;
    //
    let Some(local_client) = local_cluster.take_client() else {
        return Err(Error::Other("failed to get local cluster client".into()));
    };

    // let service_controller =
    //     start_service_controller(local_client.clone(), endpoint_slice_state, cancel.clone());
    //
    // let service_handle = tokio::spawn(service_controller);

    let identity_controller = start_identity_controllers(local_client, cancel.clone());

    let identity_handle = tokio::spawn(identity_controller);

    ready.cancel();
    tokio::select! {
        _ = cancel.cancelled() => {},
        _ = identity_handle => {}
    }

    Ok(())
}
