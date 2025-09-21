use crate::Result;
use k8s_openapi::api::core::v1::Node;
use kube::api::PostParams;
use kube::{Api, ResourceExt};

const TAINT_MESH_STARTUP: &str = "mesh-cni.dev/startup";
pub async fn remove_startup_taint(client: kube::Client, node_name: String) -> Result<()> {
    let node_api: Api<Node> = Api::all(client);
    let mut this_node = node_api.get(&node_name).await?;
    if let Some(ref mut spec) = this_node.spec
        && let Some(ref mut taints) = spec.taints
    {
        taints.retain(|t| t.key != TAINT_MESH_STARTUP);
        spec.taints = Some(taints.to_vec());
        node_api
            .replace(&this_node.name_any(), &PostParams::default(), &this_node)
            .await?;
    }

    Ok(())
}
