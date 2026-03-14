use chrono::Utc;
use k8s_openapi::{
    api::core::v1::{Node, NodeCondition, NodeStatus},
    apimachinery::pkg::apis::meta::v1::Time,
};
use kube::{
    Api, ResourceExt,
    api::{Patch, PatchParams, PostParams},
};
use serde::Serialize;

use crate::Result;

const TAINT_MESH_STARTUP: &str = "mesh-cni.dev/startup";
const TAINT_CILIUM_STARTUP: &str = "node.cilium.io/agent-not-ready";
pub async fn remove_startup_taint(client: kube::Client, node_name: String) -> Result<()> {
    let node_api: Api<Node> = Api::all(client);
    let mut this_node = node_api.get(&node_name).await?;
    if let Some(ref mut spec) = this_node.spec
        && let Some(ref mut taints) = spec.taints
    {
        taints.retain(|t| !(t.key == TAINT_MESH_STARTUP || t.key == TAINT_CILIUM_STARTUP));
        spec.taints = Some(taints.to_vec());
        node_api
            .replace(&this_node.name_any(), &PostParams::default(), &this_node)
            .await?;
    }

    Ok(())
}

#[derive(Serialize, Debug)]
struct NodeStatusPatch {
    status: NodeStatus,
}
pub async fn set_network_ready(client: kube::Client, node_name: String) -> Result<()> {
    let node_api: Api<Node> = Api::all(client);
    let now = Time(Utc::now());

    let patch = NodeStatusPatch {
        status: NodeStatus {
            conditions: Some(vec![NodeCondition {
                last_heartbeat_time: Some(now.clone()),
                last_transition_time: Some(now),
                message: Some("mesh-cni network is ready".to_string()),
                reason: Some("MeshCNIReady".to_string()),
                status: "False".to_string(),
                type_: "NetworkUnavailable".to_string(),
            }]),
            ..Default::default()
        },
    };

    node_api
        .patch_status(
            &node_name,
            &PatchParams::default(),
            &Patch::Strategic(&patch),
        )
        .await?;

    Ok(())
}
