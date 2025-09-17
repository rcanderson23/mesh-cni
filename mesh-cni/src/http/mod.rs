mod error;
mod metrics;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::select;
use tokio_util::sync::CancellationToken;

use crate::Result;

pub async fn serve_metrics(
    addr: SocketAddr,
    ready: CancellationToken,
    cancel: CancellationToken,
) -> Result<()> {
    let state = Arc::new(metrics::State::new(ready));

    metrics::serve(addr, state, cancel).await
}

pub(crate) async fn shutdown(cancel: CancellationToken) {
    select! {
        _ = cancel.cancelled() => {}
    }
}
