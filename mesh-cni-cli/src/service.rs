use mesh_cni_api::service::v1::{ListServicesRequest, service_client::ServiceClient};
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
