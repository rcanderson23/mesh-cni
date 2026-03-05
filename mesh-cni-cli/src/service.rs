use mesh_cni_api::service::v1::{
    ListNodePortsRequest, ListServicesRequest, service_client::ServiceClient,
};
use tonic::{Request, transport::Channel};

use crate::{
    cli::{OutputFormat, ServiceCommands},
    client::MESH_CNI_SOCKET,
    output,
};

pub(crate) async fn run(cmd: ServiceCommands) -> anyhow::Result<()> {
    let client = ServiceClient::connect(MESH_CNI_SOCKET).await?;
    match cmd {
        ServiceCommands::List { from_map, output } => list(client, from_map, output).await?,
        ServiceCommands::ListNodePorts { output } => list_nodeports(client, output).await?,
    }
    Ok(())
}

async fn list(
    mut client: ServiceClient<Channel>,
    from_map: bool,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let response = client
        .list_services(Request::new(ListServicesRequest { from_map }))
        .await?;
    let services = response.into_inner().services;
    output::print(services, output)
}

async fn list_nodeports(
    mut client: ServiceClient<Channel>,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let response = client
        .list_node_ports(Request::new(ListNodePortsRequest {}))
        .await?;
    let nodeports = response.into_inner().node_ports;
    output::print(nodeports, output)
}
