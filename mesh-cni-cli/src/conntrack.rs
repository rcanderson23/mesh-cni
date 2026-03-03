use mesh_cni_api::conntrack::v1::{GetConntrackRequest, conntrack_client::ConntrackClient};
use tonic::{Request, transport::Channel};

use crate::{
    cli::{ConntrackCommands, OutputFormat},
    client::MESH_CNI_SOCKET,
    output,
};

pub(crate) async fn run(cmd: ConntrackCommands) -> anyhow::Result<()> {
    let client = ConntrackClient::connect(MESH_CNI_SOCKET).await?;
    match cmd {
        ConntrackCommands::List { output } => list(client, output).await?,
    }
    Ok(())
}

async fn list(mut client: ConntrackClient<Channel>, output: OutputFormat) -> anyhow::Result<()> {
    let response = client
        .get_conntrack(Request::new(GetConntrackRequest::default()))
        .await?;
    let connections = response.into_inner().connections;
    output::print(connections, output)
}
