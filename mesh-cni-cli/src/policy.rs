use mesh_cni_api::policy::v1::{ListPolicyRequest, policy_client::PolicyClient};
use tabled::{Table, settings::Style};
use tonic::{Request, transport::Channel};

use crate::{cli::PolicyCommands, client::MESH_CNI_SOCKET};

pub(crate) async fn run(cmd: PolicyCommands) -> anyhow::Result<()> {
    let client = PolicyClient::connect(MESH_CNI_SOCKET).await?;
    match cmd {
        PolicyCommands::List => list(client).await?,
    }
    Ok(())
}

async fn list(mut client: PolicyClient<Channel>) -> anyhow::Result<()> {
    let response = client
        .list_policy(Request::new(ListPolicyRequest::default()))
        .await?;
    let policies = response.into_inner().policies;

    let table = Table::new(policies).with(Style::empty()).to_string();
    println!("{table}");
    Ok(())
}
