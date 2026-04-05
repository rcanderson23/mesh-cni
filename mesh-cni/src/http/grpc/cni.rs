use std::{
    net::{IpAddr, Ipv4Addr},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::anyhow;
use aya::programs::{
    SchedClassifier, TcAttachType,
    links::{FdLink, LinkError, PinnedLink},
    tc,
};
use ipnetwork::{IpNetwork, Ipv4Network};
use kube::{ResourceExt, runtime::reflector::ObjectRef};
use mesh_cni_api::cni::v1::{
    AddPodReply, AddPodRequest, DeletePodReply, DeletePodRequest, Interface, Ip,
    cni_server::Cni as CniApi,
};
use mesh_cni_crds::v1alpha1::identity::Identity;
use mesh_cni_ebpf_common::route::RouteV4;
use mesh_cni_k8s_utils::sanitize_pod_labels;
use mesh_cni_netlink::Netlink;
use mesh_cni_policy_controller::{Context, PolicyDataplane, reconcile_identity};
use sha2::{Digest, Sha256};
use tokio::time::{Duration, sleep};
use tonic::{Code, Request, Response, Status};
use tracing::{error, info, warn};

use crate::{
    Result,
    bpf::{
        BPF_MESH_LINKS_DIR, BPF_PROGRAM_EGRESS_TC, BPF_PROGRAM_INGRESS_TC,
        BPF_PROGRAM_VXLAN_VETH_EGRESS_TC,
    },
    config::CniMode,
};

pub struct CniState<P, I, R>
where
    P: ReconcilePolicy + Send + Sync + 'static,
    I: Ipam + Send + Sync + 'static,
    R: Routes + Send + Sync + 'static,
{
    policy_reconciler: P,
    netns_dir: PathBuf,
    ipam: I,
    mode: CniMode,
    routes: R,
}

pub trait Ipam {
    /// Return the first non-network IP Addr
    fn first_v4(&self) -> Result<Ipv4Addr>;
    /// Allocate a IPv4 Address
    fn allocate_v4_ip(&self) -> Result<Ipv4Addr>;
    /// Return the IPv4 Address back to the pool
    fn release_v4_ip(&self, ip: Ipv4Addr) -> Result<()>;
    /// Returns the length of bits for the shared prefix
    fn network_length_v4(&self) -> u8;
}

// TODO: modify this trait to be IP agnostic
pub trait Routes {
    /// Add route to BPF map for pod to pod traffic
    fn add_route_v4(&self, key: IpNetwork, value: RouteV4) -> Result<()>;
    /// Remove route from BPF map for pod to pod traffic
    fn delete_route_v4(&self, key: &IpNetwork) -> Result<()>;
}

const MESH_LINK_PREFIX: &str = "mesh_cni_link_";

impl<P, I, R> CniState<P, I, R>
where
    P: ReconcilePolicy + Send + Sync + 'static,
    I: Ipam + Send + Sync + 'static,
    R: Routes + Send + Sync + 'static,
{
    pub fn new(
        policy_reconciler: P,
        netns_dir: PathBuf,
        ipam: I,
        mode: CniMode,
        routes: R,
    ) -> Self {
        Self {
            policy_reconciler,
            netns_dir,
            ipam,
            mode,
            routes,
        }
    }
}

// Spec says there SHOULD be a DEL call in between ADD calls so we need
// to try to clean up on failed attach and pin calls
//
// NetworkPolicy states that policy should be enforced during the entire lifecycle of
// the pod so we need reconcile policy on pod creation which requires identity lookup.
// This is fairly likely to fail on the first call when creating a pod that generates
// a new Identity CR but will be retried by the CNI/kubelet and should be fast
// on subsequent calls
#[tonic::async_trait]
impl<P, I, R> CniApi for CniState<P, I, R>
where
    P: ReconcilePolicy + Clone + Send + Sync + 'static,
    I: Ipam + Clone + Send + Sync + 'static,
    R: Routes + Clone + Send + Sync + 'static,
{
    async fn add_pod(
        &self,
        request: Request<AddPodRequest>,
    ) -> std::result::Result<Response<AddPodReply>, Status> {
        // TODO: replace logging here with request middleware on the tonic server
        info!("received add request {:?}", request);

        let reconciler = self.policy_reconciler.clone();
        let req = request.into_inner();
        let netns_dir = self.netns_dir.clone();
        let mode = self.mode.clone();
        let ipam = self.ipam.clone();
        let routes = self.routes.clone();

        // To simplify logic in the add_pod call and switching network namespaces, we will spawn a
        // new thread and runtime
        let reply = tokio::task::spawn_blocking(move || -> Result<AddPodReply> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(add_pod(reconciler, req, netns_dir, mode, ipam, routes))
        })
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(reply))
    }

    async fn delete_pod(
        &self,
        request: Request<DeletePodRequest>,
    ) -> std::result::Result<Response<DeletePodReply>, Status> {
        let request = request.into_inner();
        info!("received delete request {:?}", request);
        let host_veth = host_veth_name(&request.container_id);

        for iface in [&request.iface, host_veth.as_str(), "lo"] {
            unpin_iface_paths(&request.container_id, iface)
                .map_err(|e| tonic::Status::new(Code::Internal, e.to_string()))?;
        }

        let req = request.clone();
        let netns_dir = self.netns_dir.clone();
        let mode = self.mode.clone();
        let ipam = self.ipam.clone();
        let routes = self.routes.clone();

        // To simplify logic in the delete_pod call and switching network namespaces, we will spawn a
        // new thread and runtime
        let reply = tokio::task::spawn_blocking(move || -> Result<DeletePodReply> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(delete_pod(req, netns_dir, mode, ipam, routes))
        })
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(reply))
    }
}

async fn delete_pod<I: Ipam, R: Routes>(
    request: DeletePodRequest,
    netns_dir: PathBuf,
    mode: CniMode,
    ipam: I,
    routes: R,
) -> Result<DeletePodReply> {
    let Some(netns) = &request.net_namespace else {
        warn!(iface = %request.iface, "skipping delete_pod for interface without sandbox");
        return Ok(DeletePodReply::default());
    };
    let netns_path = netns_path(netns_dir, netns)?;
    if !netns_path.exists() {
        warn!(
            iface = %request.iface,
            netns = %netns_path.display(),
            "skipping delete_pod cleanup because sandbox no longer exists",
        );
        return Ok(DeletePodReply::default());
    }
    let pod_ns = netns_rs::get_from_path(netns_path)?;
    let host_netns = netns_rs::get_from_current_thread()?;
    let _nsguard = NetnsRestore(host_netns);
    pod_ns.enter()?;
    let nl = Netlink::try_new()?;
    let addrs = nl.get_iface_addrs(&request.iface).await?;

    // TODO: support ipv6
    // TODO: Ipam and routes is susceptiple to exhaustion if deletes happen where the network namespace is
    // destroyed prior to releasing.
    for addr in addrs {
        match addr {
            IpAddr::V4(ipv4_addr) => {
                routes.delete_route_v4(&IpNetwork::V4(Ipv4Network::new(ipv4_addr, 32)?))?;
                if mode == CniMode::Vxlan {
                    ipam.release_v4_ip(ipv4_addr)?;
                }
            }
            IpAddr::V6(_) => continue,
        }
    }

    Ok(DeletePodReply::default())
}

async fn add_pod<P: ReconcilePolicy, I: Ipam, R: Routes>(
    reconciler: P,
    request: AddPodRequest,
    netns_dir: PathBuf,
    mode: CniMode,
    ipam: I,
    routes: R,
) -> Result<AddPodReply> {
    let Some(netns) = &request.net_namespace else {
        warn!(iface = %request.iface, "skipping add_pod for interface without sandbox");
        return Ok(AddPodReply::default());
    };
    let mut last_error = None;
    for attempt in 0..5 {
        match reconciler.reconcile_policy(&request.pod_name, &request.pod_namespace) {
            Ok(()) => {
                last_error = None;
                break;
            }
            Err(e @ PolicyReconcileError::PodNotFound { .. })
            | Err(e @ PolicyReconcileError::IdentityError { .. }) => {
                last_error = Some(e);
                let backoff_ms = 500u64.saturating_mul(1 + attempt);
                sleep(Duration::from_millis(backoff_ms)).await;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    if let Some(e) = last_error {
        return Err(e.into());
    }

    let reply: AddPodReply = match mode {
        CniMode::Chained => add_chained(&request, netns, netns_dir, routes).await?,
        CniMode::Vxlan => add_vxlan(&request, netns, netns_dir, ipam).await?,
    };
    Ok(reply)
}

// WHen in vxlan we need to setup the primary network interface for the pod as well as its peer. We
// do this by creating the veth pair inside the pod network namespace, bringing up the interfaces,
// attaching bpf programs to the primary pod interface as well as lo for network policy enforcement
// on hairpin traffic. The peer interface needs to be moved to the host network namespace and then
// assinged its gateway addr and brought up.
//
// The reply message expects to know the IPs and interfaces given to the pod.
async fn add_vxlan<I: Ipam>(
    request: &AddPodRequest,
    netns: &str,
    netns_dir: PathBuf,
    ipam: I,
) -> Result<AddPodReply> {
    let host_netns = netns_rs::get_from_current_thread()?;
    let host_fd = host_netns.file().as_raw_fd();
    let nsguard = NetnsRestore(host_netns);
    let pod_netns_path = netns_path(netns_dir, netns)?;
    let pod_ns = netns_rs::get_from_path(pod_netns_path)?;
    pod_ns.enter()?;

    let addr = ipam.allocate_v4_ip()?;
    let addr_prefix = ipam.network_length_v4();
    let first = ipam.first_v4()?;

    let host_veth_name = host_veth_name(&request.container_id);

    let nl = Netlink::try_new()?;
    let (ifindex, veth_idx) = nl.create_veth_pair(&request.iface, &host_veth_name).await?;

    attach_pod_bpf(&request.iface, &request.container_id)?;

    nl.set_link_up(ifindex).await?;

    nl.set_link_up(veth_idx).await?;

    nl.set_addr(ifindex, IpAddr::V4(addr)).await?;

    nl.add_link_scope_route(ifindex, IpAddr::V4(first), 32)
        .await?;

    nl.add_default_route(ifindex, IpAddr::V4(first)).await?;

    nl.set_iface_to_netns(veth_idx, host_fd).await?;

    drop(nsguard);

    let nl = Netlink::try_new()?;
    let host_veth_ifindex = nl.get_link_index_by_name(&host_veth_name).await?;

    nl.set_addr(host_veth_ifindex, IpAddr::V4(first)).await?;

    nl.set_link_up(host_veth_ifindex).await?;

    nl.add_host_route(host_veth_ifindex, IpAddr::V4(addr))
        .await?;

    attach_and_pin_links(
        &host_veth_name,
        &request.container_id,
        BPF_PROGRAM_VXLAN_VETH_EGRESS_TC.path(),
        TcAttachType::Ingress, // need to be ingress attach coming from the pod netns
    )?;

    Ok(AddPodReply {
        interfaces: vec![
            Interface {
                name: request.iface.clone(),
                sandbox: Some(netns.to_string()),
                ..Default::default()
            },
            Interface {
                name: host_veth_name.clone(),
                sandbox: None,
                ..Default::default()
            },
        ],
        ips: vec![Ip {
            address: format!("{}/{}", addr, addr_prefix),
            gateway: first.to_string(),
            iface: Some(0),
        }],
        ..Default::default()
    })
}

async fn add_chained<R: Routes>(
    request: &AddPodRequest,
    netns: &str,
    netns_dir: PathBuf,
    routes: R,
) -> Result<AddPodReply> {
    let reply = AddPodReply::default();
    let host_netns = netns_rs::get_from_current_thread()?;
    let _nsguard = NetnsRestore(host_netns);
    let pod_netns_path = netns_path(netns_dir, netns)?;
    let pod_ns = netns_rs::get_from_path(pod_netns_path)?;
    pod_ns.enter()?;

    attach_pod_bpf(&request.iface, &request.container_id)?;
    let nl = Netlink::try_new()?;
    let addrs = nl.get_iface_addrs(&request.iface).await?;
    let link_ifindex = nl.get_link_index_by_name(&request.iface).await?;
    // TODO: support ipv6
    for addr in addrs {
        match addr {
            IpAddr::V4(ipv4_addr) => {
                routes.add_route_v4(
                    IpNetwork::V4(Ipv4Network::new(ipv4_addr, 32)?),
                    RouteV4::new_local(link_ifindex),
                )?;
            }
            IpAddr::V6(_) => continue,
        }
    }

    Ok(reply)
}

fn attach_pod_bpf(pod_iface: &str, container_id: &str) -> Result<()> {
    let mut attached = Vec::new();

    for iface in [pod_iface, "lo"] {
        if let Err(e) = attach_for_iface(
            iface,
            container_id,
            TcAttachType::Ingress,
            TcAttachType::Egress,
        ) {
            error!(%e, "failed to attach tc programs");
            for attached_iface in attached {
                if let Err(u) = unpin_iface_paths(container_id, attached_iface) {
                    error!(%u, "failed to unpin path");
                };
            }
            return Err(e);
        }
        attached.push(iface);
    }
    Ok(())
}

// linux iface names are resetricted to 16 characters
fn host_veth_name(container_id: &str) -> String {
    let digest = Sha256::digest(container_id.as_bytes());
    let hex = format!("{:x}", digest);

    format!("mesh{}", &hex[..11])
}

fn unpin_path(path: impl AsRef<Path>) -> Result<()> {
    match path.as_ref().try_exists() {
        Ok(true) => {}
        Ok(false) => return Ok(()),
        Err(e) => {
            return Err(e.into());
        }
    }
    match PinnedLink::from_pin(path) {
        Ok(link) => {
            let _link = link.unpin()?;
        }
        Err(LinkError::SyscallError(err))
            if err.io_error.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn pin_path(container_id: &str, iface: &str, attach_type: TcAttachType) -> PathBuf {
    let container_id = container_id.replace('/', "_");
    let iface = iface.replace('/', "_");
    let link_name = format!("{}_{}", container_id, iface);
    match attach_type {
        TcAttachType::Ingress => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{link_name}_ingress", MESH_LINK_PREFIX)),
        TcAttachType::Egress => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{link_name}_egress", MESH_LINK_PREFIX)),
        TcAttachType::Custom(_) => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{link_name}_custom", MESH_LINK_PREFIX)),
    }
}

fn attach_and_pin_links(
    iface: &str,
    container_id: &str,
    path: impl AsRef<Path>,
    attach_type: TcAttachType,
) -> Result<()> {
    let pin_path = pin_path(container_id, iface, attach_type);
    if pin_path.try_exists()? {
        return Ok(());
    }

    let mut prog = SchedClassifier::from_pin(path)?;

    let _ = tc::qdisc_add_clsact(iface);

    let link_id = prog.attach(iface, attach_type)?;

    let link = prog.take_link(link_id)?;
    let link: FdLink = link.try_into()?;
    link.pin(pin_path)?;
    Ok(())
}

fn unpin_iface_paths(container_id: &str, iface: &str) -> Result<()> {
    let ingress_path = pin_path(container_id, iface, TcAttachType::Ingress);
    let egress_path = pin_path(container_id, iface, TcAttachType::Egress);

    for path in [ingress_path, egress_path] {
        unpin_path(path)?;
    }
    Ok(())
}

fn attach_for_iface(
    iface: &str,
    container_id: &str,
    ingress_attach_type: TcAttachType,
    egress_attach_type: TcAttachType,
) -> Result<()> {
    attach_and_pin_links(
        iface,
        container_id,
        BPF_PROGRAM_INGRESS_TC.path(),
        ingress_attach_type,
    )?;

    if let Err(e) = attach_and_pin_links(
        iface,
        container_id,
        BPF_PROGRAM_EGRESS_TC.path(),
        egress_attach_type,
    ) {
        if let Err(u) = unpin_iface_paths(container_id, iface) {
            error!(%u, "failed to unpin path");
        };
        return Err(e);
    }

    Ok(())
}

fn netns_path(mut netns_dir: PathBuf, netns: &str) -> Result<PathBuf> {
    let netns_name = PathBuf::from(netns);
    let netns_name = netns_name
        .file_name()
        .ok_or(anyhow!("failed to get file name from netns path"))?
        .to_str()
        .ok_or(anyhow!("failed to convert netns path file to str"))?;
    netns_dir.push(netns_name);
    Ok(netns_dir)
}

pub trait ReconcilePolicy {
    fn reconcile_policy(
        &self,
        pod_name: &str,
        pod_namespace: &str,
    ) -> std::result::Result<(), PolicyReconcileError>;
}

impl<P: PolicyDataplane + Send + Sync + 'static> ReconcilePolicy for Arc<Context<P>> {
    fn reconcile_policy(
        &self,
        pod_name: &str,
        pod_namespace: &str,
    ) -> std::result::Result<(), PolicyReconcileError> {
        let Some(pod) = self
            .pod_store
            .get(&ObjectRef::new(pod_name).within(pod_namespace))
        else {
            return Err(PolicyReconcileError::PodNotFound {
                name: pod_name.to_string(),
                namespace: pod_namespace.to_string(),
            });
        };

        let identities: Vec<Arc<Identity>> = self
            .identity_store
            .state()
            .iter()
            .filter(|i| {
                let mut pod_labels = pod.labels().to_owned();
                sanitize_pod_labels(&mut pod_labels);
                i.namespace() == pod.namespace() && i.spec.pod_labels == pod_labels
            })
            .cloned()
            .collect();

        match identities.as_slice() {
            [] => Err(PolicyReconcileError::IdentityError(
                "no identity found".to_string(),
            )),
            [identity] => {
                reconcile_identity(identity.clone(), self.clone())
                    .map_err(|e| PolicyReconcileError::Other(e.into()))?;
                Ok(())
            }
            _ => Err(PolicyReconcileError::IdentityError(
                "more than one identity found".to_string(),
            )),
        }
    }
}

#[derive(Debug)]
pub enum PolicyReconcileError {
    PodNotFound { name: String, namespace: String },
    IdentityError(String),
    Other(anyhow::Error),
}

impl std::fmt::Display for PolicyReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyReconcileError::PodNotFound { name, namespace } => {
                write!(f, "failed to find pod in store: {namespace}/{name}")
            }
            PolicyReconcileError::IdentityError(error) => {
                write!(f, "{error}")
            }
            PolicyReconcileError::Other(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for PolicyReconcileError {}

struct NetnsRestore(netns_rs::NetNs);

impl Drop for NetnsRestore {
    fn drop(&mut self) {
        let _ = self.0.enter();
    }
}
