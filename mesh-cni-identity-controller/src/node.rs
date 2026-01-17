use std::{net::IpAddr, str::FromStr, sync::Arc};

use k8s_openapi::api::core::v1::Node;
use kube::{ResourceExt, runtime::controller::Action};
use tracing::{debug, info};

use crate::{
    IdentityBpfState, IdentityControllerExt, Result, context::Context,
    controller::DEFAULT_REQUEUE_DURATION,
};

const LOCAL_NODE_ID: u32 = 10;
const REMOTE_NODE_ID: u32 = 11;

impl IdentityControllerExt for Node {
    async fn reconcile<B: IdentityBpfState>(&self, ctx: Arc<Context<B>>) -> Result<Action> {
        let node_name = self.name_any();

        info!("Started reconciling Node {}", node_name);

        let ips = node_ips(self);

        let id = if node_name == ctx.node_name {
            LOCAL_NODE_ID
        } else {
            REMOTE_NODE_ID
        };
        for ip in ips {
            let prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            let ip_net = ipnetwork::IpNetwork::new(ip, prefix)?;
            ctx.bpf_maps.update(ip_net, id)?;
            debug!("Added IP/Identity {}/{}", ip, id);
        }

        Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
    }
}

fn node_ips(node: &Node) -> Vec<IpAddr> {
    let Some(status) = node.status.as_ref() else {
        return Vec::new();
    };

    let Some(addrs) = status.addresses.as_ref() else {
        return Vec::new();
    };

    addrs
        .iter()
        .filter_map(|na| IpAddr::from_str(&na.address).ok())
        .collect()
}
