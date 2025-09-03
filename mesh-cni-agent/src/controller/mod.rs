use k8s_openapi::api::core::v1::Service;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::config::ControllerArgs;
use crate::kubernetes::cluster::{Cluster, ClusterConfigs};
use crate::kubernetes::state::GlobalState;
use crate::{Error, Result, kubernetes};

pub async fn start(args: ControllerArgs, cancel: CancellationToken) -> Result<()> {
    let configs = ClusterConfigs::try_new_configs(args.mesh_clusters_config).await?;
    let mut clusters = vec![];
    let local_cluster = Cluster::try_new(configs.local).await?;
    for config in configs.remote {
        let Ok(cluster) = Cluster::try_new(config).await else {
            warn!("failed to create cluster from config");
            continue;
        };
        clusters.push(cluster);
    }
    clusters.push(local_cluster);

    let mut service_state: GlobalState<Service> =
        kubernetes::state::GlobalState::try_new(clusters).await?;

    let Some(rx) = service_state.take_receiver() else {
        return Err(Error::Other(
            "global cluster store receiver not present".into(),
        ));
    };
    let mut rx = rx;
    while let Some(event) = rx.recv().await {
        println!(
            "received event in cluster {} for service {:?}",
            event.cluster.name, event.resource
        );
    }
    Ok(())
}
