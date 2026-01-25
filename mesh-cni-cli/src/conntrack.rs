use mesh_cni_api::conntrack::v1::{GetConntrackRequest, conntrack_client::ConntrackClient};
use tabled::{Table, settings::Style};
use tonic::{Request, transport::Channel};

use crate::{cli::ConntrackCommands, client::MESH_CNI_SOCKET};

pub(crate) async fn run(cmd: ConntrackCommands) -> anyhow::Result<()> {
    let client = ConntrackClient::connect(MESH_CNI_SOCKET).await?;
    match cmd {
        ConntrackCommands::List => list(client).await?,
    }
    Ok(())
}

async fn list(mut client: ConntrackClient<Channel>) -> anyhow::Result<()> {
    let response = client
        .get_conntrack(Request::new(GetConntrackRequest::default()))
        .await?;
    let connections = response.into_inner().connections;

    let table = Table::new(connections).with(Style::modern()).to_string();
    println!("{table}");
    Ok(())
}
