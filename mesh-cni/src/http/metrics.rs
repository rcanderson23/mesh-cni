use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router,
    extract::State as AxumState,
    response::{IntoResponse, Response},
    routing::get,
};
use http::StatusCode;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{Result, http::shutdown};

#[derive(Clone)]
pub(crate) struct State {
    ready: CancellationToken,
}

impl State {
    pub fn new(token: CancellationToken) -> Self {
        Self { ready: token }
    }
    pub fn ready(&self) -> Readiness {
        if self.ready.is_cancelled() {
            Readiness::Ready
        } else {
            Readiness::NotReady
        }
    }
    pub fn metrics(&self) -> String {
        let mut buffer = String::new();
        let registry = &*crate::metrics::REGISTRY.read().unwrap();
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
        .route("/readyz", get(readyz))
        .with_state(state))
}

async fn metrics(AxumState(handler): AxumState<Arc<State>>) -> String {
    handler.metrics()
}

async fn readyz(AxumState(handler): AxumState<Arc<State>>) -> Readiness {
    handler.ready()
}

pub(crate) enum Readiness {
    Ready,
    NotReady,
}
impl IntoResponse for Readiness {
    fn into_response(self) -> axum::response::Response {
        match self {
            Readiness::Ready => Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .body(axum::body::Body::from("Ok"))
                .unwrap(),
            Readiness::NotReady => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "text/plain")
                .body(axum::body::Body::from("NotReady"))
                .unwrap(),
        }
    }
}
