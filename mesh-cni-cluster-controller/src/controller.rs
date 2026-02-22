use std::{sync::Arc, time::Duration};

use k8s_openapi::api::core::v1::Secret;
use kube::{
    Api, Client, Config, ResourceExt,
    api::{DeleteParams, ListParams},
    config::{KubeConfigOptions, Kubeconfig},
    core::{Expression, Selector},
    runtime::{controller::Action, finalizer, reflector::ObjectRef},
};
use mesh_cni_crds::v1alpha1::{
    cluster::{self, Cluster},
    meshendpoint::MeshEndpoint,
};
use mesh_cni_meshendpoint_gen_controller::{
    LABEL_CLUSTER_OWNER, start_meshendpoint_gen_controller,
};
use serde::de::DeserializeOwned;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{Error, Result, context::Context};

const CLUSTER_FINALIZER: &str = "clusters.mesh-cni.dev/cleanup";
const DEFAULT_REQUEUE: Duration = Duration::from_secs(300);
const ERROR_REQUEUE: Duration = Duration::from_secs(5);

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
    {
        let reader = ctx.controllers.read().unwrap();
        if reader.get(&cluster.name_any()).is_some() {
            return Ok(Action::requeue(DEFAULT_REQUEUE));
        }
    }

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

    let kubeconfig = kubeconfig_from_secret_data(&secret, &secret_name, &secret_key)?;
    let source_client = client_from_kubeconfig(kubeconfig).await?;
    let local_client = ctx.client.clone();
    let cancel = CancellationToken::new();

    let handle = start_meshendpoint_gen_controller(
        local_client,
        source_client,
        cluster.name_any(),
        cancel.child_token(),
    )
    .await
    .map_err(|e| Error::StartUpFailed(e.to_string()))?;

    let mut guard = ctx.controllers.write().unwrap();

    guard.insert(cluster.name_any(), (cancel, handle));

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
        let Some((cancellation, handle)) = reader.get(&name) else {
            return Ok(Action::await_change());
        };
        cancellation.cancel();
        if !handle.is_finished() {
            info!("controller handle for {name} is not finished, requeuing");
            return Err(Error::ControllerRunning);
        }
    }

    delete_owned_meshendpoints(ctx.client.clone(), name.clone()).await?;

    let mut writer = ctx.controllers.write().unwrap();
    writer.remove(&name);
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

async fn delete_owned_meshendpoints(client: Client, cluster_name: String) -> Result<()> {
    let meshendpoint: Api<MeshEndpoint> = Api::all(client.clone());

    let selector: Selector =
        Expression::Equal(LABEL_CLUSTER_OWNER.to_string(), cluster_name).into();
    let lp = ListParams::default().labels_from(&selector);
    let meps = meshendpoint.list_metadata(&lp).await?;

    let dp = DeleteParams::default();
    for obj in meps.iter() {
        let Some(ns) = obj.namespace() else {
            return Ok(());
        };
        let meshendpoint: Api<MeshEndpoint> = Api::namespaced(client.clone(), &ns);
        meshendpoint.delete(&obj.name_any(), &dp).await?;
    }
    Ok(())
}
