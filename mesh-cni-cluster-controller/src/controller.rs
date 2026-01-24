use std::{sync::Arc, time::Duration};

use kube::{
    Api, ResourceExt,
    runtime::{controller::Action, finalizer},
};
use mesh_cni_crds::v1alpha1::cluster::Cluster;
use serde::de::DeserializeOwned;
use tracing::{error, info};

use crate::{Error, Result, context::Context};

const CLUSTER_FINALIZER: &str = "clusters.mesh-cni.dev/cleanup";
const SHUTDOWN_REQUEUE: Duration = Duration::from_secs(5);
const DEFAULT_REQUEUE: Duration = Duration::from_secs(300);

pub(crate) async fn reconcile(cluster: Arc<Cluster>, ctx: Arc<Context>) -> Result<Action> {
    let name = cluster.name_any();
    let api: Api<Cluster> = Api::all(ctx.client.clone());

    info!("Reconciling Cluster {}", name);
    finalizer(&api, CLUSTER_FINALIZER, cluster, |event| async {
        match event {
            finalizer::Event::Apply(cluster) => reconcile_cluster(cluster, ctx).await,
            finalizer::Event::Cleanup(cluster) => cleanup(cluster, ctx).await,
        }
    })
    .await?;

    Ok(Action::requeue(DEFAULT_REQUEUE))
}

async fn reconcile_cluster(_cluster: Arc<Cluster>, _ctx: Arc<Context>) -> Result<Action> {
    Ok(Action::requeue(DEFAULT_REQUEUE))
}

async fn cleanup(cluster: Arc<Cluster>, ctx: Arc<Context>) -> Result<Action> {
    let name = cluster.name_any();
    let mut controllers = ctx.controllers.lock().unwrap();
    if let Some(cancellation) = controllers.get(&name) {
        cancellation.request_shutdown();
        if !cancellation.is_shutdown_complete() {
            return Ok(Action::requeue(SHUTDOWN_REQUEUE));
        }
    }
    controllers.remove(&name);
    Ok(Action::await_change())
}

pub fn error_policy<K>(resource: Arc<K>, error: &Error, _ctx: Arc<Context>) -> Action
where
    K: kube::ResourceExt<DynamicType = ()>,
    K: DeserializeOwned + Clone + Send + Sync + std::fmt::Debug + 'static,
{
    let name = resource.name_any();
    error!(?error, "reconcile error for Cluster {}", name);
    Action::requeue(Duration::from_secs(5))
}
