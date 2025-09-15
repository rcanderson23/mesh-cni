use mesh_cni_api::service::v1::ListServicesRequest;
use mesh_cni_api::service::v1::service_client::ServiceClient;
use tabled::Table;
use tabled::settings::Style;
use tonic::Request;
use tonic::transport::Channel;

use crate::cli::ServiceCommands;
use crate::client::{self, MESH_CNI_SOCKET};

pub(crate) async fn run(cmd: ServiceCommands) -> anyhow::Result<()> {
    let client = ServiceClient::connect(MESH_CNI_SOCKET).await?;
    match cmd {
        ServiceCommands::List => list(client).await?,
    }
    Ok(())
}

async fn list(mut client: ServiceClient<Channel>) -> anyhow::Result<()> {
    let response = client
        .list_services(Request::new(ListServicesRequest::default()))
        .await?;
    let services = response.into_inner().services;

    let table = Table::new(services).with(Style::modern()).to_string();
    println!("{table}");
    Ok(())
}
