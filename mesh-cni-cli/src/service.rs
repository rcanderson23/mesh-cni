use mesh_cni_api::service::v1::{ListServicesRequest, service_client::ServiceClient};
use tabled::{Table, settings::Style};
use tonic::{Request, transport::Channel};

use crate::{cli::ServiceCommands, client::MESH_CNI_SOCKET};

pub(crate) async fn run(cmd: ServiceCommands) -> anyhow::Result<()> {
    let client = ServiceClient::connect(MESH_CNI_SOCKET).await?;
    match cmd {
        ServiceCommands::List { from_map } => list(client, from_map).await?,
    }
    Ok(())
}

async fn list(mut client: ServiceClient<Channel>, from_map: bool) -> anyhow::Result<()> {
    let response = client
        .list_services(Request::new(ListServicesRequest { from_map }))
        .await?;
    let services = response.into_inner().services;

    let table = Table::new(services).with(Style::empty()).to_string();
    println!("{table}");
    Ok(())
}
