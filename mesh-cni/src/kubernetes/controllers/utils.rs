use mesh_cni_ebpf_common::KubeProtocol;
use tokio_util::sync::CancellationToken;

pub(crate) async fn shutdown(cancel: CancellationToken) {
    tokio::select! {
        _ = cancel.cancelled() => {}
    }
}

pub fn kube_proto_from_str(proto: &Option<String>) -> KubeProtocol {
    match proto {
        Some(p) => KubeProtocol::try_from(p.as_str()).unwrap_or_default(),
        None => KubeProtocol::Tcp,
    }
}
