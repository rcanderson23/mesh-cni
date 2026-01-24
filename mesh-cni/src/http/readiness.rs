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
        .route("/readyz", get(readyz))
        .with_state(state))
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
