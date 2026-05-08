use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    Api, Client,
    runtime::{Config, Controller},
};
use mesh_cni_k8s_utils::create_store_and_touched_subscriber;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Context, HostPortDataplane, Result,
    controller::{error_policy, reconcile},
    utils::shutdown,
};

pub async fn start_hostport_bpf_service_controller<B>(
    kube_client: Client,
    hostport_bpf_state: B,
    node_name: &str,
    cancel: CancellationToken,
) -> Result<()>
where
    B: HostPortDataplane + Clone + Send + Sync + 'static,
{
    let pod_api: Api<Pod> = Api::all(kube_client.clone());
    let config = kube::runtime::watcher::Config::default();
    let config = config.fields(&format!("spec.nodeName={node_name}"));
    let (pod_state, pod_subscriber) =
        create_store_and_touched_subscriber(pod_api, config, Some(Duration::from_secs(30))).await?;

    let context = Arc::new(Context {
        pod_state: pod_state.clone(),
        kube_client: kube_client.clone(),
        hostport_bpf_state,
    });

    let ctrl_config = Config::default().concurrency(10);

    info!("Starting Pod hostport controller");
    Controller::for_shared_stream(pod_subscriber, pod_state)
        .with_config(ctrl_config)
        .graceful_shutdown_on(shutdown(cancel))
        .run(reconcile, error_policy::<B>, context)
        .for_each(|_| futures::future::ready(()))
        .await;
    Ok(())
}
