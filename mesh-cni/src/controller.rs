use std::sync::Arc;

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
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
    let mut clusters = vec![];
    let mut local_cluster = Cluster::try_new(configs.local).await?;
    for config in configs.remote {
        let Ok(cluster) = Cluster::try_new(config).await else {
            warn!("failed to create cluster from config");
            continue;
        };
        clusters.push(cluster);
    }
    clusters.push(local_cluster.clone());

    let mut service_state: MultiClusterState<Service> =
        kubernetes::state::MultiClusterState::try_new(clusters.clone()).await?;
    let mut endpoint_slice_state: MultiClusterState<EndpointSlice> =
        kubernetes::state::MultiClusterState::try_new(clusters).await?;

    let Some(_svc_rx) = service_state.take_receiver() else {
        return Err(Error::Other(
            "multi cluster store receiver not present".into(),
        ));
    };
    let Some(_eps_rx) = endpoint_slice_state.take_receiver() else {
        return Err(Error::Other(
            "multi cluster store receiver not present".into(),
        ));
    };

    let _service_state = Arc::new(service_state);
    let endpoint_slice_state = Arc::new(endpoint_slice_state);

    let Some(local_client) = local_cluster.take_client() else {
        return Err(Error::Other("failed to get local cluster client".into()));
    };

    let service_controller =
        start_service_controller(local_client, endpoint_slice_state, cancel.clone());

    tokio::spawn(service_controller);

    ready.cancel();
    tokio::select! {
        _ = cancel.cancelled() => {},
    }

    Ok(())
}
