use anyhow::Context;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

pub const MESH_CNI_SOCKET: &str = "unix:///var/run/mesh/mesh.sock";
