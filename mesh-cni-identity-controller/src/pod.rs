use std::{net::IpAddr, str::FromStr, sync::Arc};

use k8s_openapi::api::core::v1::Pod;
use kube::{
    ResourceExt,
    runtime::{controller::Action, reflector::ObjectRef},
};
use tracing::{debug, info};

use crate::{
    Error, IdentityBpfState, IdentityControllerExt, Result, context::Context,
    controller::DEFAULT_REQUEUE_DURATION,
};

const PENDING_POD_IP_REQUEUE_DURATION: std::time::Duration = std::time::Duration::from_secs(1);

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

        let ips = pod_ips(self);
        if self.metadata.deletion_timestamp.is_some() {
            for ip in ips {
                let prefix = match ip {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                let ip_net = ipnetwork::IpNetwork::new(ip, prefix)?;
                ctx.bpf_maps.delete(ip_net)?;
                debug!("Removed IP/Identity mapping for deleted pod IP {}", ip);
            }
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

        if ips.is_empty() {
            return Ok(Action::requeue(PENDING_POD_IP_REQUEUE_DURATION));
        }

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

pub(crate) fn pod_ips(pod: &Pod) -> Vec<IpAddr> {
    let Some(status) = pod.status.as_ref() else {
        return Vec::new();
    };

    if let Some(ips) = status.pod_ips.as_ref() {
        return ips
            .iter()
            .filter_map(|ip| IpAddr::from_str(&ip.ip).ok())
            .collect();
    }

    status
        .pod_ip
        .as_deref()
        .and_then(|ip| IpAddr::from_str(ip).ok())
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::{PodIP, PodStatus};

    use super::*;

    #[test]
    fn pod_ips_uses_status_pod_ips_when_present() {
        let pod = Pod {
            status: Some(PodStatus {
                pod_ips: Some(vec![
                    PodIP {
                        ip: "10.0.0.2".into(),
                    },
                    PodIP {
                        ip: "fd00::2".into(),
                    },
                ]),
                pod_ip: Some("10.0.0.9".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let ips = pod_ips(&pod);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&IpAddr::from_str("10.0.0.2").unwrap()));
        assert!(ips.contains(&IpAddr::from_str("fd00::2").unwrap()));
    }

    #[test]
    fn pod_ips_falls_back_to_status_pod_ip() {
        let pod = Pod {
            status: Some(PodStatus {
                pod_ips: None,
                pod_ip: Some("10.0.0.7".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let ips = pod_ips(&pod);
        assert_eq!(ips, vec![IpAddr::from_str("10.0.0.7").unwrap()]);
    }
}
