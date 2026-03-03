use mesh_cni_api::policy::v1::{ListPolicyRequest, policy_client::PolicyClient};
use tonic::{Request, transport::Channel};

use crate::{
    cli::{OutputFormat, PolicyCommands},
    client::MESH_CNI_SOCKET,
    output,
};

pub(crate) async fn run(cmd: PolicyCommands) -> anyhow::Result<()> {
    let client = PolicyClient::connect(MESH_CNI_SOCKET).await?;
    match cmd {
        PolicyCommands::List { output } => list(client, output).await?,
    }
    Ok(())
}

async fn list(mut client: PolicyClient<Channel>, output: OutputFormat) -> anyhow::Result<()> {
    let response = client
        .list_policy(Request::new(ListPolicyRequest::default()))
        .await?;
    let policies = response.into_inner().policies;
    output::print(policies, output)
}
