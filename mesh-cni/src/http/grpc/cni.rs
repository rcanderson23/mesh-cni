use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use futures::TryFutureExt;
use ipnetwork::{IpNetwork, Ipv4Network};
use kube::{ResourceExt, runtime::reflector::ObjectRef};
use mesh_cni_api::cni::v1::{
    AddChainedReply, AddChainedRequest, AddVxlanReply, AddVxlanRequest, DeletePodReply,
    DeletePodRequest, cni_server::Cni as CniApi,
};
use mesh_cni_crds::v1alpha1::identity::Identity;
use mesh_cni_ebpf_common::route::RouteV4;
use mesh_cni_k8s_utils::sanitize_pod_labels;
use mesh_cni_policy_controller::{Context, PolicyDataplane, reconcile_identity};
use tokio::time::{Duration, sleep};
use tonic::{Request, Response, Status};
use tracing::info;

use crate::Result;

pub struct CniState<P, I, R>
where
    P: ReconcilePolicy + Send + Sync + 'static,
    I: Ipam + Send + Sync + 'static,
    R: Routes + Send + Sync + 'static,
{
    policy_reconciler: P,
    ipam: I,
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

impl<P, I, R> CniState<P, I, R>
where
    P: ReconcilePolicy + Send + Sync + 'static,
    I: Ipam + Send + Sync + 'static,
    R: Routes + Send + Sync + 'static,
{
    pub fn new(policy_reconciler: P, ipam: I, routes: R) -> Self {
        Self {
            policy_reconciler,
            ipam,
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
    async fn add_vxlan_pod(
        &self,
        request: Request<AddVxlanRequest>,
    ) -> std::result::Result<Response<AddVxlanReply>, Status> {
        // TODO: replace logging here with request middleware on the tonic server
        info!("received add vxlan request {:?}", request);

        let reconciler = self.policy_reconciler.clone();
        let req = request.into_inner();

        let reply = add_vxlan_pod(
            &reconciler,
            &self.ipam,
            &self.routes,
            &req.pod_name,
            &req.pod_namespace,
            req.host_ifindex,
        )
        .map_err(|e| Status::internal(e.to_string()))
        .await?;

        Ok(Response::new(reply))
    }
    async fn add_chained_pod(
        &self,
        request: Request<AddChainedRequest>,
    ) -> std::result::Result<Response<AddChainedReply>, Status> {
        // TODO: replace logging here with request middleware on the tonic server
        info!("received add vxlan request {:?}", request);

        let reconciler = self.policy_reconciler.clone();
        let req = request.into_inner();

        let reply = add_chained_pod(&reconciler, &req.pod_name, &req.pod_namespace)
            .map_err(|e| Status::internal(e.to_string()))
            .await?;

        Ok(Response::new(reply))
    }

    async fn delete_pod(
        &self,
        request: Request<DeletePodRequest>,
    ) -> std::result::Result<Response<DeletePodReply>, Status> {
        let request = request.into_inner();
        info!("received delete request {:?}", request);

        let addrs = request
            .ipv4
            .iter()
            .map(|bytes| bytes_to_addr(bytes))
            .collect::<Result<Vec<_>>>()
            .map_err(|e| Status::internal(e.to_string()))?;
        let reply = delete_pod(&self.ipam, &self.routes, &addrs)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(reply))
    }
}

async fn delete_pod<I: Ipam, R: Routes>(
    ipam: &I,
    routes: &R,
    addrs: &[IpAddr],
) -> Result<DeletePodReply> {
    // TODO: support ipv6
    // TODO: Ipam and routes is susceptiple to exhaustion if deletes happen where the network namespace is
    // destroyed prior to releasing.
    for addr in addrs {
        match addr {
            IpAddr::V4(ipv4_addr) => {
                routes.delete_route_v4(&IpNetwork::V4(Ipv4Network::new(*ipv4_addr, 32)?))?;
                ipam.release_v4_ip(*ipv4_addr)?;
            }
            IpAddr::V6(_) => continue,
        }
    }

    Ok(DeletePodReply::default())
}

async fn add_vxlan_pod<P: ReconcilePolicy, I: Ipam, R: Routes>(
    reconciler: &P,
    ipam: &I,
    routes: &R,
    pod_name: &str,
    pod_namespace: &str,
    ifindex: u32,
) -> Result<AddVxlanReply> {
    let mut last_error = None;
    for attempt in 0..5 {
        match reconciler.reconcile_policy(pod_name, pod_namespace) {
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

    let mut reply = AddVxlanReply::default();
    let ipv4 = ipam.allocate_v4_ip()?;
    routes.add_route_v4(
        IpNetwork::V4(Ipv4Network::new(ipv4, 32)?),
        RouteV4::new_local(ifindex),
    )?;
    reply.ipv4 = ipv4.octets().to_vec();
    reply.ipv4_gateway = ipam.first_v4()?.octets().to_vec();

    Ok(reply)
}

async fn add_chained_pod<P: ReconcilePolicy>(
    reconciler: &P,
    pod_name: &str,
    pod_namespace: &str,
) -> Result<AddChainedReply> {
    let mut last_error = None;
    for attempt in 0..5 {
        match reconciler.reconcile_policy(pod_name, pod_namespace) {
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

    Ok(AddChainedReply::default())
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

fn bytes_to_addr(bytes: &[u8]) -> Result<IpAddr> {
    match bytes.len() {
        4 => {
            let octets: [u8; 4] = bytes.try_into().unwrap();
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        16 => {
            let octets: [u8; 16] = bytes.try_into().unwrap();
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err(anyhow::anyhow!(
            "bytes length was not 4 or 16, got {}",
            bytes.len()
        )),
    }
}
