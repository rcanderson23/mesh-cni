use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use k8s_openapi::api::core::v1::Pod;
use kube::{
    Api, ResourceExt,
    runtime::{
        controller::Action,
        finalizer::{Event, finalizer},
    },
};
use mesh_cni_ebpf_common::{
    KubeProtocol,
    hostport::{
        HostPortKey, HostPortKeyV4, HostPortKeyV6, HostPortValue, HostPortValueV4, HostPortValueV6,
    },
};
use tracing::{error, info, warn};

use crate::{Context, Error, HostPortDataplane, Result};

const FINALIZER: &str = "mesh.cni/hostport";
const DEFAULT_REQUEUE_DURATION: Duration = Duration::from_secs(300);
const ERROR_REQUEUE_DURATION: Duration = Duration::from_secs(5);

pub(crate) async fn reconcile<B: HostPortDataplane>(
    pod: Arc<Pod>,
    ctx: Arc<Context<B>>,
) -> Result<Action> {
    let ns = pod
        .namespace()
        .ok_or_else(|| Error::MissingPrecondition("missing namespace".into()))?;
    let ns_name = format!("{}/{}", ns, pod.name_any());
    info!("started reconciling Pod {}", ns_name);

    let hostports = get_pod_hostports(&pod)?;
    if hostports.is_empty() {
        return Ok(Action::await_change());
    }

    let pod_api: Api<Pod> = Api::namespaced(ctx.kube_client.clone(), &ns);
    finalizer(&pod_api, FINALIZER, pod, |event| {
        let ctx = Arc::clone(&ctx);
        async move {
            match event {
                Event::Apply(pod) => apply(pod, ctx, hostports).await,
                Event::Cleanup(pod) => cleanup(pod, ctx).await,
            }
        }
    })
    .await
    .map_err(|e| Error::Other(e.to_string()))
}

async fn apply<B: HostPortDataplane>(
    pod: Arc<Pod>,
    ctx: Arc<Context<B>>,
    hostports: Vec<PodHostPort>,
) -> Result<Action> {
    if is_terminal_pod(&pod) {
        remove_hostports(hostports, &ctx)?;
        return Ok(Action::await_change());
    }

    for host_port_backend in get_pod_hostport_backends(&pod)? {
        let protocol = host_port_backend.protocol as u8;
        let key = hostport_backend_key(&host_port_backend);
        let value = match host_port_backend.pod_ip {
            IpAddr::V4(ipv4_addr) => HostPortValue::V4(HostPortValueV4::new(
                ipv4_addr.to_bits(),
                host_port_backend.container_port,
                protocol,
            )),
            IpAddr::V6(ipv6_addr) => HostPortValue::V6(HostPortValueV6::new(
                ipv6_addr.to_bits(),
                host_port_backend.container_port,
                protocol,
            )),
        };
        ctx.hostport_bpf_state.upsert_hostport(key, value)?;
    }

    Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
}

async fn cleanup<B: HostPortDataplane>(pod: Arc<Pod>, ctx: Arc<Context<B>>) -> Result<Action> {
    remove_hostports(get_pod_hostports(&pod)?, &ctx)?;
    Ok(Action::await_change())
}

fn remove_hostports<B: HostPortDataplane>(
    hostports: Vec<PodHostPort>,
    ctx: &Context<B>,
) -> Result<()> {
    for podhostport in hostports {
        let key = hostport_key(&podhostport);
        ctx.hostport_bpf_state.remove_hostport(&key)?;
    }
    Ok(())
}

pub(crate) fn error_policy<B: HostPortDataplane>(
    pod: Arc<Pod>,
    error: &Error,
    _ctx: Arc<Context<B>>,
) -> Action {
    let ns = pod.namespace().unwrap_or_default();
    let ns_name = format!("{}/{}", ns, pod.name_any());
    error!(%error, "error reconciling {}", ns_name);
    Action::requeue(ERROR_REQUEUE_DURATION)
}

fn is_terminal_pod(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|status| status.phase.as_deref())
        .is_some_and(|phase| matches!(phase, "Succeeded" | "Failed"))
}

struct PodHostPort {
    container_port: u16,
    host_port: u16,
    host_ip: IpAddr,
    protocol: KubeProtocol,
}

struct PodHostPortBackend {
    container_port: u16,
    host_port: u16,
    host_ip: IpAddr,
    pod_ip: IpAddr,
    protocol: KubeProtocol,
}

fn hostport_key(pod_host_port: &PodHostPort) -> HostPortKey {
    match pod_host_port.host_ip {
        IpAddr::V4(ipv4_addr) => HostPortKey::V4(HostPortKeyV4::new(
            ipv4_addr.to_bits(),
            pod_host_port.host_port,
            pod_host_port.protocol as u8,
        )),
        IpAddr::V6(ipv6_addr) => HostPortKey::V6(HostPortKeyV6::new(
            ipv6_addr.to_bits(),
            pod_host_port.host_port,
            pod_host_port.protocol as u8,
        )),
    }
}

fn hostport_backend_key(host_port_backend: &PodHostPortBackend) -> HostPortKey {
    match host_port_backend.host_ip {
        IpAddr::V4(ipv4_addr) => HostPortKey::V4(HostPortKeyV4::new(
            ipv4_addr.to_bits(),
            host_port_backend.host_port,
            host_port_backend.protocol as u8,
        )),
        IpAddr::V6(ipv6_addr) => HostPortKey::V6(HostPortKeyV6::new(
            ipv6_addr.to_bits(),
            host_port_backend.host_port,
            host_port_backend.protocol as u8,
        )),
    }
}

fn get_pod_hostports(pod: &Pod) -> Result<Vec<PodHostPort>> {
    let mut host_ports = Vec::default();
    let Some(spec) = &pod.spec else {
        return Ok(host_ports);
    };

    for container in &spec.containers {
        let Some(ports) = &container.ports else {
            continue;
        };
        for port in ports {
            let Some(host_port) = port.host_port else {
                continue;
            };
            let Ok(host_port) = u16::try_from(host_port) else {
                warn!(
                    "failed to convert container host_port {} on pod {}",
                    host_port,
                    pod.name_any()
                );
                continue;
            };
            let Ok(container_port) = u16::try_from(port.container_port) else {
                warn!(
                    "failed to convert container port {} on pod {}",
                    port.container_port,
                    pod.name_any()
                );
                continue;
            };
            let Ok(protocol) = KubeProtocol::try_from(port.protocol.as_deref()) else {
                warn!(
                    "failed to convert container port protocol {} on pod {}",
                    host_port,
                    pod.name_any()
                );
                continue;
            };
            if protocol == KubeProtocol::Sctp {
                warn!(
                    "skipping unsupported SCTP hostPort {} on pod {}",
                    host_port,
                    pod.name_any()
                );
                continue;
            }
            let explicit_host_ip = port
                .host_ip
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(|e| Error::Other(format!("failed to convert host_ip: {}", e)))?;

            match explicit_host_ip {
                Some(host_ip) => host_ports.push(PodHostPort {
                    container_port,
                    host_port,
                    host_ip,
                    protocol,
                }),
                None => {
                    host_ports.push(PodHostPort {
                        container_port,
                        host_port,
                        host_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        protocol,
                    });
                    host_ports.push(PodHostPort {
                        container_port,
                        host_port,
                        host_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                        protocol,
                    });
                }
            }
        }
    }

    Ok(host_ports)
}

fn get_pod_hostport_backends(pod: &Pod) -> Result<Vec<PodHostPortBackend>> {
    let mut backends = Vec::default();
    let pod_addrs = pod_ips(pod);

    for hostport in get_pod_hostports(pod)? {
        for &pod_ip in &pod_addrs {
            match (hostport.host_ip, pod_ip) {
                (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                    backends.push(PodHostPortBackend {
                        container_port: hostport.container_port,
                        host_port: hostport.host_port,
                        host_ip: hostport.host_ip,
                        pod_ip,
                        protocol: hostport.protocol,
                    });
                }
                (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => continue,
            }
        }
    }

    Ok(backends)
}

fn pod_ips(pod: &Pod) -> Vec<IpAddr> {
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
