use std::sync::Arc;

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Patch, PatchParams};
use kube::runtime::conditions;
use kube::runtime::wait::await_condition;
use kube::{Api, CustomResourceExt};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::ControllerArgs;
use crate::kubernetes::cluster::{Cluster, ClusterConfigs};
use crate::kubernetes::crds::meshendpoint::NAME_GROUP_MESHENDPOINT;
use crate::kubernetes::state::MultiClusterState;
use crate::{Error, Result, kubernetes};

pub async fn start(args: ControllerArgs, cancel: CancellationToken) -> Result<()> {
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

    let service_state = Arc::new(service_state);
    let endpoint_slice_state = Arc::new(endpoint_slice_state);

    let Some(local_client) = local_cluster.take_client() else {
        return Err(Error::Other("failed to get local cluster client".into()));
    };

    apply_crds(local_client.clone()).await?;

    let service_controller = crate::kubernetes::controllers::service::start_service_controller(
        local_client,
        service_state,
        endpoint_slice_state,
        cancel.clone(),
    );

    tokio::select! {
        h = service_controller => exit("service_controller", h),
        _ = cancel.cancelled() => {},
    }

    Ok(())
}

pub async fn apply_crds(client: kube::Client) -> Result<()> {
    let crds: Api<CustomResourceDefinition> = Api::all(client);
    let ssaply = PatchParams::apply("mesh_cni").force();
    crds.patch(
        NAME_GROUP_MESHENDPOINT,
        &ssaply,
        &Patch::Apply(&crate::kubernetes::crds::meshendpoint::v1alpha1::MeshEndpoint::crd()),
    )
    .await?;
    let established = await_condition(
        crds,
        NAME_GROUP_MESHENDPOINT,
        conditions::is_crd_established(),
    );
    // TODO: FIXME
    match tokio::time::timeout(std::time::Duration::from_secs(5), established).await {
        Ok(o) => o?,

        Err(e) => return Err(Error::Other(e.to_string())),
    };
    info!("applied MeshEndpoint CRD");
    Ok(())
}

fn exit(task: &str, out: Result<()>) {
    match out {
        Ok(_) => {
            info!("{task} exited")
        }
        Err(e) => {
            error!("{task} failed with error: {e}")
        }
    }
}
