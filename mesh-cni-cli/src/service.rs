use mesh_cni_api::service::v1::ListServicesRequest;
use mesh_cni_api::service::v1::service_client::ServiceClient;
use tabled::Table;
use tabled::settings::Style;
use tonic::Request;
use tonic::transport::Channel;

use crate::cli::ServiceCommands;
use crate::client;

pub(crate) async fn run(cmd: ServiceCommands) -> anyhow::Result<()> {
    let service_client = client::channel().await?;
    let service_client = ServiceClient::new(service_client);
    match cmd {
        ServiceCommands::List => list(service_client).await?,
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
