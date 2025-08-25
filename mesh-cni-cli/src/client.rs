use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

const MESH_CNI_SOCKET: &str = "/var/run/mesh/mesh.sock";

pub async fn channel() -> anyhow::Result<Channel> {
    let channel = Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(|_: Uri| async {
            Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(MESH_CNI_SOCKET).await?))
        }))
        .await?;
    Ok(channel)
}
