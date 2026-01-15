use tokio_util::sync::CancellationToken;

pub(crate) async fn shutdown(cancel: CancellationToken) {
    tokio::select! {
        _ = cancel.cancelled() => {}
    }
}
