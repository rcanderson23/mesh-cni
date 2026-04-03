use mesh_cni_api::cni::v1::cni_client::CniClient;
use tonic::transport::Channel;

use crate::Error;

pub(crate) async fn new_cni_client() -> Result<CniClient<Channel>, Error> {
    let path = "unix:///var/run/mesh/mesh.sock";
    let client = CniClient::connect(path).await?;
    Ok(client)
}
