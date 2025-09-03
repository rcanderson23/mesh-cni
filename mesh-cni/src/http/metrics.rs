use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State as AxumState;
use axum::routing::get;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::Result;
use crate::http::shutdown;
use crate::metrics::Metrics;

#[derive(Clone)]
pub(crate) struct State {
    metrics: Arc<Metrics>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            metrics: Arc::new(Metrics::default()),
        }
    }
}

impl State {
    pub fn metrics(&self) -> String {
        let mut buffer = String::new();
        let registry = &*self.metrics.registry;
        // TODO: get rid of unwrap
        match prometheus_client::encoding::text::encode(&mut buffer, registry) {
            Ok(_) => buffer,
            Err(_) => "".into(),
        }
    }
}

pub(crate) async fn serve(
    addr: SocketAddr,
    state: Arc<State>,
    cancel: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("metrics listening on {}", addr);

    let app = router(state)?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown(cancel))
        .await?;
    Ok(())
}

pub fn router(state: Arc<State>) -> Result<Router> {
    Ok(Router::new()
        .route("/metrics", get(metrics))
        .with_state(state))
}

async fn metrics(AxumState(handler): AxumState<Arc<State>>) -> String {
    handler.metrics()
}
