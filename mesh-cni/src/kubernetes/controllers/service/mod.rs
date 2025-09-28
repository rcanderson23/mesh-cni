mod context;
mod controller;

use std::{ops::Deref, sync::Arc, task::Poll};

use futures::{Stream, StreamExt};
use k8s_openapi::api::{core::v1::Service, discovery::v1::EndpointSlice};
use kube::{
    Api, Client,
    runtime::{Controller, watcher::Config},
};
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    Result,
    kubernetes::{
        controllers::{
            metrics::ControllerMetrics,
            service::{
                context::Context,
                controller::{error_policy, reconcile},
            },
        },
        crds::meshendpoint::v1alpha1::MeshEndpoint,
        create_store_and_subscriber,
        state::MultiClusterState,
    },
};

pub async fn start_service_controller(
    client: Client,
    mut endpoint_slice_state: MultiClusterState<EndpointSlice>,
    cancel: CancellationToken,
) -> Result<()> {
    let service_api: Api<Service> = Api::all(client.clone());
    let mesh_ep_api: Api<MeshEndpoint> = Api::all(client.clone());

    let (mesh_endpoint_state, _) = create_store_and_subscriber(mesh_ep_api).await?;
    let endpoint_slice_receiver = endpoint_slice_state
        .take_receiver()
        .ok_or_else(|| crate::Error::Other("missing endpoint slice receiver".into()))?;
    let metrics = ControllerMetrics::new("meshendpoint-services");
    let context = Context {
        metrics,
        client,
        endpoint_slice_state,
        mesh_endpoint_state,
    };

    info!("starting mesh service controller");
    Controller::new(service_api, Config::default().any_semantic())
        .graceful_shutdown_on(crate::kubernetes::controllers::utils::shutdown(cancel))
        .owns_stream(EndpointSliceStream::new(endpoint_slice_receiver))
        .run(reconcile, error_policy, Arc::new(context))
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
    Ok(())
}

struct EndpointSliceStream {
    inner: Receiver<Arc<EndpointSlice>>,
}

impl EndpointSliceStream {
    fn new(receiver: Receiver<Arc<EndpointSlice>>) -> Self {
        Self { inner: receiver }
    }
}

impl Stream for EndpointSliceStream {
    type Item = std::result::Result<EndpointSlice, kube::runtime::watcher::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match &self.inner.poll_recv(cx) {
            std::task::Poll::Ready(r) => match r {
                Some(eps) => Poll::Ready(Some(Ok(eps.deref().clone()))),
                None => Poll::Pending,
            },
            std::task::Poll::Pending => Poll::Pending,
        }
    }
}
