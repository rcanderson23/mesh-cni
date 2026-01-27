use mesh_cni_api::ip::v1::{ListIpsRequest, ip_client::IpClient};
use tabled::{Table, settings::Style};
use tonic::{Request, transport::Channel};

use crate::{cli::IpCommands, client::MESH_CNI_SOCKET};

pub(crate) async fn run(cmd: IpCommands) -> anyhow::Result<()> {
    let client = IpClient::connect(MESH_CNI_SOCKET).await?;
    match cmd {
        IpCommands::List => list(client).await?,
    }
    Ok(())
}

async fn list(mut client: IpClient<Channel>) -> anyhow::Result<()> {
    let response = client
        .list_ips(Request::new(ListIpsRequest::default()))
        .await?;
    let ips = response.into_inner().ips;

    let table = Table::new(ips).with(Style::empty()).to_string();
    println!("{table}");
    Ok(())
}
