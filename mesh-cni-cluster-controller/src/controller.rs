use std::{sync::Arc, time::Duration};

use k8s_openapi::api::core::v1::Secret;
use kube::{
    Api, Client, Config, ResourceExt,
    api::{DeleteParams, ListParams, PartialObjectMeta},
    config::{KubeConfigOptions, Kubeconfig},
    core::{Expression, Selector},
    runtime::{controller::Action, finalizer, reflector::ObjectRef},
};
use mesh_cni_crds::v1alpha1::{
    cluster::Cluster, meshendpoint::MeshEndpoint, meshidentityslice::MeshIdentitySlice,
};
use mesh_cni_meshendpoint_gen_controller::{
    LABEL_CLUSTER_OWNER, start_meshendpoint_gen_controller,
};
use mesh_cni_meshidentityslice_gen_controller::start_meshidentityslice_gen_controller;
use serde::de::DeserializeOwned;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{
    Error, Result,
    context::{ClusterControllerState, Context},
};

const CLUSTER_FINALIZER: &str = "clusters.mesh-cni.dev/cleanup";
const DEFAULT_REQUEUE: Duration = Duration::from_secs(300);
const ERROR_REQUEUE: Duration = Duration::from_secs(5);
const CHILD_CONTROLLER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

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

async fn reconcile_cluster(cluster: Arc<Cluster>, ctx: Arc<Context>) -> Result<Action> {
    let cluster_name = cluster.name_any();
    let secret_name = cluster.spec.secret.name.clone();
    let secret_key = cluster
        .spec
        .secret
        .key
        .clone()
        .unwrap_or("config".to_string());
    let Some(secret) = ctx
        .secrets
        .get(&ObjectRef::new(&secret_name).within(&ctx.namespace))
    else {
        return Err(Error::ResourceNotFound {
            kind: "Secret".to_string(),
            name: secret_name.clone(),
        });
    };
    let secret_resource_version = secret.metadata.resource_version.clone().unwrap_or_default();
    {
        let reader = ctx.controllers.read().unwrap();
        if let Some(state) = reader.get(&cluster_name)
            && state.secret_name == secret_name
            && state.secret_key == secret_key
            && state.secret_resource_version == secret_resource_version
        {
            return Ok(Action::requeue(DEFAULT_REQUEUE));
        }
    }

    {
        let mut writer = ctx.controllers.write().unwrap();
        if let Some(existing) = writer.get(&cluster_name) {
            existing.cancellation.cancel();
            if !controllers_finished(existing) {
                info!("controller handle for {cluster_name} is not finished, requeuing");
                return Err(Error::ControllerRunning);
            }
            writer.remove(&cluster_name);
        }
    }

    let kubeconfig = kubeconfig_from_secret_data(&secret, &secret_name, &secret_key)?;
    let source_client = client_from_kubeconfig(kubeconfig).await?;
    let local_client = ctx.client.clone();
    let cancel = CancellationToken::new();

    let mut meshendpoint_handle = start_meshendpoint_gen_controller(
        local_client,
        source_client.clone(),
        cluster_name.clone(),
        cancel.child_token(),
    )
    .await
    .map_err(|e| Error::StartUpFailed(e.to_string()))?;
    let meshidentityslice_handle = match start_meshidentityslice_gen_controller(
        ctx.client.clone(),
        source_client,
        cluster_name.clone(),
        cancel.child_token(),
    )
    .await
    {
        Ok(handle) => handle,
        Err(e) => {
            error!(
                cluster = %cluster_name,
                error = %e,
                "failed to start meshidentityslice controller, cancelling already-started meshendpoint controller",
            );
            cancel.cancel();
            match tokio::time::timeout(CHILD_CONTROLLER_SHUTDOWN_TIMEOUT, &mut meshendpoint_handle)
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(join_err)) => {
                    error!(
                        cluster = %cluster_name,
                        error = %join_err,
                        "meshendpoint controller exited with join error during startup rollback",
                    );
                }
                Err(_) => {
                    error!(
                        cluster = %cluster_name,
                        timeout_secs = CHILD_CONTROLLER_SHUTDOWN_TIMEOUT.as_secs(),
                        "timed out waiting for meshendpoint controller shutdown, aborting",
                    );
                    meshendpoint_handle.abort();
                    if let Err(join_err) = meshendpoint_handle.await
                        && !join_err.is_cancelled()
                    {
                        error!(
                            cluster = %cluster_name,
                            error = %join_err,
                            "meshendpoint controller returned join error after abort",
                        );
                    }
                }
            }
            return Err(Error::StartUpFailed(e.to_string()));
        }
    };

    let mut guard = ctx.controllers.write().unwrap();
    guard.insert(
        cluster_name,
        ClusterControllerState {
            cancellation: cancel,
            meshendpoint_handle,
            meshidentityslice_handle,
            secret_name,
            secret_key,
            secret_resource_version,
        },
    );

    Ok(Action::requeue(DEFAULT_REQUEUE))
}

fn kubeconfig_from_secret_data(
    secret: &Secret,
    secret_name: &str,
    key: &str,
) -> Result<Kubeconfig> {
    let kubeconfig =
        secret
            .data
            .as_ref()
            .and_then(|data| data.get(key))
            .ok_or(Error::KubeconfigNotFound {
                name: secret_name.to_string(),
                key: key.to_string(),
            })?;

    Ok(serde_yaml::from_slice(&kubeconfig.0)?)
}

async fn client_from_kubeconfig(kubeconfig: Kubeconfig) -> Result<Client> {
    let config = Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
        .await
        .map_err(|e| Error::Other(e.to_string()))?;
    Ok(Client::try_from(config)?)
}

async fn cleanup(cluster: Arc<Cluster>, ctx: Arc<Context>) -> Result<Action> {
    let name = cluster.name_any();
    {
        let reader = ctx.controllers.read().unwrap();
        if let Some(state) = reader.get(&name) {
            state.cancellation.cancel();
            if !controllers_finished(state) {
                info!("controller handle for {name} is not finished, requeuing");
                return Err(Error::ControllerRunning);
            }
        }
    }

    let remaining = delete_owned_meshendpoints(ctx.client.clone(), name.clone()).await?
        + delete_owned_meshidentityslices(ctx.client.clone(), name.clone()).await?;
    if remaining > 0 {
        return Err(Error::CleanupPending);
    }

    ctx.controllers.write().unwrap().remove(&name);
    Ok(Action::await_change())
}

pub fn error_policy<K>(resource: Arc<K>, error: &Error, _ctx: Arc<Context>) -> Action
where
    K: kube::ResourceExt<DynamicType = ()>,
    K: DeserializeOwned + Clone + Send + Sync + std::fmt::Debug + 'static,
{
    let name = resource.name_any();
    error!(?error, "reconcile error for Cluster {}", name);
    Action::requeue(ERROR_REQUEUE)
}

/// Deletes the meshendpoints owned by the cluster
// TODO: This is listing from the cluster, consider using a store cache
async fn delete_owned_meshendpoints(client: Client, cluster_name: String) -> Result<usize> {
    let meshendpoint: Api<MeshEndpoint> = Api::all(client.clone());

    let selector: Selector =
        Expression::Equal(LABEL_CLUSTER_OWNER.to_string(), cluster_name).into();
    let lp = ListParams::default().labels_from(&selector);
    let meps = meshendpoint.list_metadata(&lp).await?;

    let dp = DeleteParams::default();
    for obj in meps.iter() {
        let Some(ns) = obj.namespace() else {
            return Err(Error::InvalidResource);
        };
        let meshendpoint: Api<MeshEndpoint> = Api::namespaced(client.clone(), &ns);
        meshendpoint.delete(&obj.name_any(), &dp).await?;
    }
    let meps = meshendpoint.list_metadata(&lp).await?;
    let meps: Vec<&PartialObjectMeta<MeshEndpoint>> = meps
        .iter()
        .filter(|m| m.metadata.deletion_timestamp.is_none())
        .collect();
    Ok(meps.len())
}

async fn delete_owned_meshidentityslices(client: Client, cluster_name: String) -> Result<usize> {
    let meshidentityslices: Api<MeshIdentitySlice> = Api::all(client.clone());

    let selector: Selector =
        Expression::Equal(LABEL_CLUSTER_OWNER.to_string(), cluster_name).into();
    let lp = ListParams::default().labels_from(&selector);
    let slices = meshidentityslices.list_metadata(&lp).await?;

    let dp = DeleteParams::default();
    for obj in slices.iter() {
        let Some(ns) = obj.namespace() else {
            return Err(Error::InvalidResource);
        };
        let meshidentityslices: Api<MeshIdentitySlice> = Api::namespaced(client.clone(), &ns);
        meshidentityslices.delete(&obj.name_any(), &dp).await?;
    }
    let slices = meshidentityslices.list_metadata(&lp).await?;
    let slices: Vec<&PartialObjectMeta<MeshIdentitySlice>> = slices
        .iter()
        .filter(|m| m.metadata.deletion_timestamp.is_none())
        .collect();
    Ok(slices.len())
}

fn controllers_finished(state: &ClusterControllerState) -> bool {
    state.meshendpoint_handle.is_finished() && state.meshidentityslice_handle.is_finished()
}
