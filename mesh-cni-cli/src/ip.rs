use mesh_cni_api::ip::v1::{ListIpsRequest, ip_client::IpClient};
use tonic::{Request, transport::Channel};

use crate::{
    cli::{IpCommands, OutputFormat},
    client::MESH_CNI_SOCKET,
    output,
};

pub(crate) async fn run(cmd: IpCommands) -> anyhow::Result<()> {
    let client = IpClient::connect(MESH_CNI_SOCKET).await?;
    match cmd {
        IpCommands::List { output } => list(client, output).await?,
    }
    Ok(())
}

async fn list(mut client: IpClient<Channel>, output: OutputFormat) -> anyhow::Result<()> {
    let response = client
        .list_ips(Request::new(ListIpsRequest::default()))
        .await?;
    let ips = response.into_inner().ips;
    output::print(ips, output)
}
