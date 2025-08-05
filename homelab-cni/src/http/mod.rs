use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State as AxumState;
use axum::routing::get;
use tokio::net::TcpListener;
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::Result;
use crate::metrics::Metrics;

#[derive(Clone)]
pub struct State {
    metrics: Arc<Metrics>,
}

impl State {
    pub fn metrics(&self) -> String {
        let mut buffer = String::new();
        let registry = &*self.metrics.registry;
        prometheus_client::encoding::text::encode(&mut buffer, registry).unwrap();
        buffer
    }
}

pub async fn serve(addr: SocketAddr, state: Arc<State>, cancel: CancellationToken) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("metrics listening on {}", addr);

    let app = router(state)?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown(cancel))
        .await?;
    Ok(())
}

async fn shutdown(cancel: CancellationToken) {
    select! {
        _ = cancel.cancelled() => {}
    }
}

pub fn router(state: Arc<State>) -> Result<Router> {
    Ok(Router::new()
        .route("/metrics", get(metrics))
        .with_state(state))
}

async fn metrics(AxumState(handler): AxumState<Arc<State>>) -> String {
    handler.metrics()
}
