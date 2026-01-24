mod error;
mod readiness;

use std::{net::SocketAddr, sync::Arc};

use tokio::select;
use tokio_util::sync::CancellationToken;

use crate::Result;

pub async fn serve(
    addr: SocketAddr,
    ready: CancellationToken,
    cancel: CancellationToken,
) -> Result<()> {
    let state = Arc::new(readiness::State::new(ready));

    readiness::serve(addr, state, cancel).await
}

pub(crate) async fn shutdown(cancel: CancellationToken) {
    select! {
        _ = cancel.cancelled() => {}
    }
}
