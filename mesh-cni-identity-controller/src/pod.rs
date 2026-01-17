use std::{net::IpAddr, str::FromStr, sync::Arc};

use k8s_openapi::api::core::v1::Pod;
use kube::runtime::reflector::ObjectRef;
use kube::{ResourceExt, runtime::controller::Action};
use tracing::{debug, info};

use crate::controller::DEFAULT_REQUEUE_DURATION;
use crate::{Error, Result, context::Context};
use crate::{IdentityBpfState, IdentityControllerExt};

impl IdentityControllerExt for Pod {
    async fn reconcile<B: IdentityBpfState>(&self, ctx: Arc<Context<B>>) -> Result<Action> {
        let pod_name = self.name_any();
        let namespace = ctx
            .namespace_store
            .get(&ObjectRef::new(
                &self.namespace().ok_or(Error::InvalidResource)?,
            ))
            .ok_or(Error::ResourceNotFound)?;

        info!(
            "Started reconciling Pod {}/{}",
            namespace.name_any(),
            pod_name
        );

        if self
            .spec
            .as_ref()
            .is_some_and(|s| s.host_network == Some(true))
        {
            return Ok(Action::await_change());
        }

        let identity = ctx
            .identity_store
            .state()
            .iter()
            .find(|identity| {
                identity.namespace().as_deref() == Some(namespace.name_any().as_str())
                    && identity.pod_namespace_labels_match(self, &namespace)
            })
            .cloned()
            .ok_or(Error::ResourceNotFound)?;

        info!(
            "Matched Identity {}/{} for Pod {}/{}",
            namespace.name_any(),
            identity.name_any(),
            namespace.name_any(),
            pod_name
        );

        let ips = pod_ips(self);

        for ip in ips {
            let prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            let ip_net = ipnetwork::IpNetwork::new(ip, prefix)?;
            ctx.bpf_maps.update(ip_net, identity.spec.id)?;
            debug!("Added IP/Identity {}/{}", ip, identity.spec.id);
        }

        Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
    }
}

fn pod_ips(pod: &Pod) -> Vec<IpAddr> {
    let Some(status) = pod.status.as_ref() else {
        return Vec::new();
    };

    let Some(ips) = status.pod_ips.as_ref() else {
        return Vec::new();
    };

    ips.iter()
        .filter_map(|ip| IpAddr::from_str(&ip.ip).ok())
        .collect()
}
