mod context;
mod controller;

use std::sync::Arc;

use aya::maps::lpm_trie::Key as LpmKey;
use futures::StreamExt;
use k8s_openapi::api::core::v1::{Namespace, Pod};
use kube::{Api, Client, runtime::Controller};
use mesh_cni_common::Id;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Result,
    bpf::{BpfMap, ip::IpNetworkState},
    kubernetes::{
        ClusterId,
        controllers::ip::{
            context::Context,
            controller::{error_policy, reconcile_namespace, reconcile_pod},
        },
        create_store_and_subscriber,
    },
};

pub trait IpController {}

pub async fn start_ip_controllers<IP4, IP6>(
    client: Client,
    ip_state: IpNetworkState<IP4, IP6>,
    cluster_id: ClusterId,
    cancel: CancellationToken,
) -> Result<()>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = Id> + Send + 'static,
    IP6: BpfMap<Key = LpmKey<u128>, Value = Id> + Send + 'static,
{
    let (pod_store, pod_subscriber) =
        create_store_and_subscriber(Api::<Pod>::all(client.clone())).await?;
    let (ns_store, ns_subscriber) =
        create_store_and_subscriber(Api::<Namespace>::all(client.clone())).await?;
    let context = Context {
        ip_state,
        pod_store: pod_store.clone(),
        ns_store: ns_store.clone(),
        cluster_id,
    };
    let context = Arc::new(context);
    info!("starting pod controller");

    tokio::spawn(
        Controller::for_shared_stream(ns_subscriber, ns_store)
            .graceful_shutdown_on(crate::kubernetes::controllers::utils::shutdown(
                cancel.clone(),
            ))
            .run(reconcile_namespace, error_policy, context.clone())
            .filter_map(|x| async move { std::result::Result::ok(x) })
            .for_each(|_| futures::future::ready(())),
    );
    Controller::for_shared_stream(pod_subscriber, pod_store)
        .graceful_shutdown_on(crate::kubernetes::controllers::utils::shutdown(cancel))
        .run(reconcile_pod, error_policy, context)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
    Ok(())
}
