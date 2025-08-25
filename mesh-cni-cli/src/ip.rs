use mesh_cni_api::ip::v1::ListIpsRequest;
use mesh_cni_api::ip::v1::ip_client::IpClient;
use tabled::Table;
use tabled::settings::Style;
use tonic::Request;
use tonic::transport::Channel;

use crate::cli::IpCommands;
use crate::client;

pub(crate) async fn run(cmd: IpCommands) -> anyhow::Result<()> {
    let ip_client = client::channel().await?;
    let ip_client = mesh_cni_api::ip::v1::ip_client::IpClient::new(ip_client);
    match cmd {
        IpCommands::List => list(ip_client).await?,
    }
    Ok(())
}

async fn list(mut client: IpClient<Channel>) -> anyhow::Result<()> {
    let response = client
        .list_ips(Request::new(ListIpsRequest::default()))
        .await?;
    let ips = response.into_inner().ips;

    let table = Table::new(ips).with(Style::modern()).to_string();
    println!("{table}");
    Ok(())
}
