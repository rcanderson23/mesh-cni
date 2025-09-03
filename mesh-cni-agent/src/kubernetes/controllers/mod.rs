use tokio_util::sync::CancellationToken;

pub mod service;

async fn shutdown(cancel: CancellationToken) {
    tokio::select! {
        _ = cancel.cancelled() => {}
    }
}
