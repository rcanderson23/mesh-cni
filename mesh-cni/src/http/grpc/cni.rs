use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use aya::programs::{
    SchedClassifier, TcAttachType,
    links::{FdLink, LinkError, PinnedLink},
    tc,
};
use kube::{ResourceExt, runtime::reflector::ObjectRef};
use mesh_cni_api::cni::v1::{
    AddPodReply, AddPodRequest, DeletePodReply, DeletePodRequest, cni_server::Cni as CniApi,
};
use mesh_cni_crds::v1alpha1::identity::Identity;
use mesh_cni_k8s_utils::sanitize_pod_labels;
use mesh_cni_policy_controller::{Context, PolicyControllerBpf, reconcile_identity};
use tokio::time::{Duration, sleep};
use tonic::{Code, Request, Response, Status};
use tracing::{error, info};

use crate::{
    Result,
    bpf::{BPF_MESH_LINKS_DIR, BPF_PROGRAM_EGRESS_TC, BPF_PROGRAM_INGRESS_TC},
};

pub struct CniState<P: ReconcilePolicy + Send + Sync + 'static> {
    policy_reconciler: P,
}

const _NET_NS_DIR: &str = "/var/run/mesh/netns";
const MESH_INGRESS_LINK_PREFIX: &str = "mesh_cni_ingress_";

impl<P: ReconcilePolicy + Send + Sync + 'static> CniState<P> {
    pub fn new(policy_reconciler: P) -> Self {
        Self { policy_reconciler }
    }
}

// TODO: this only handles chained creation correctly
//
// Spec says there SHOULD be a DEL call in between ADD calls so we need
// to try to clean up on failed attach and pin calls
//
// NetworkPolicy states that policy should be enforced during the entire lifecycle of
// the pod so we need reconcile policy on pod creation which requires identity lookup.
// This is fairly likely to fail on the first call when creating a pod that generates
// a new Identity CR but will be retried by the CNI/kubelet and should be fast
// on subsequent calls
#[tonic::async_trait]
impl<P: ReconcilePolicy + Send + Sync + 'static> CniApi for CniState<P> {
    async fn add_pod(
        &self,
        request: Request<AddPodRequest>,
    ) -> std::result::Result<Response<AddPodReply>, Status> {
        let request = request.into_inner();
        info!("received add request {:?}", request);

        let mut last_error = None;
        for attempt in 0..5 {
            match self
                .policy_reconciler
                .reconcile_policy(&request.pod_name, &request.pod_namespace)
            {
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
                Err(err) => {
                    return Err(tonic::Status::new(Code::Internal, err.to_string()));
                }
            }
        }

        if let Some(e) = last_error {
            return Err(tonic::Status::new(Code::Internal, e.to_string()));
        }

        let _ = tc::qdisc_add_clsact(&request.iface);

        // Attaching to the veth on the host network means that the egress hook
        // is traffic that is going into the pod and the reverse where the ingress
        // hook is traffic leaving the pod
        info!("adding tc ingress progam to {}", &request.iface);
        attach_and_pin_links(
            &request.iface,
            BPF_PROGRAM_INGRESS_TC.path(),
            TcAttachType::Egress,
        )
        .map_err(|e| tonic::Status::new(Code::Internal, e.to_string()))?;

        info!("adding tc egress progam to {}", &request.iface);
        if let Err(e) = attach_and_pin_links(
            &request.iface,
            BPF_PROGRAM_EGRESS_TC.path(),
            TcAttachType::Ingress,
        ) {
            let ingress_path = pin_path(&request.iface, TcAttachType::Ingress);
            let egress_path = pin_path(&request.iface, TcAttachType::Egress);
            for path in [ingress_path, egress_path] {
                if let Err(u) = unpin_path(path) {
                    error!(%u, "failed to unpin path");
                };
            }

            error!(%e, "failed to attach and pin egress link");
            Err(tonic::Status::new(Code::Internal, e.to_string()))
        } else {
            Ok(Response::new(AddPodReply {
                interfaces: Vec::new(),
                ips: Vec::new(),
                routes: Vec::new(),
                dns: None,
            }))
        }
    }

    async fn delete_pod(
        &self,
        request: Request<DeletePodRequest>,
    ) -> std::result::Result<Response<DeletePodReply>, Status> {
        let request = request.into_inner();
        info!("received delete request {:?}", request);

        let ingress_path = pin_path(&request.iface, TcAttachType::Ingress);
        let egress_path = pin_path(&request.iface, TcAttachType::Egress);

        for path in [ingress_path, egress_path] {
            unpin_path(path).map_err(|e| tonic::Status::new(Code::Internal, e.to_string()))?;
        }

        Ok(Response::new(DeletePodReply {}))
    }
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

fn pin_path(iface: &str, attach_type: TcAttachType) -> PathBuf {
    match attach_type {
        TcAttachType::Ingress => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{}_ingress", MESH_INGRESS_LINK_PREFIX, iface)),
        TcAttachType::Egress => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{}_egress", MESH_INGRESS_LINK_PREFIX, iface)),
        TcAttachType::Custom(_) => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{}_custom", MESH_INGRESS_LINK_PREFIX, iface)),
    }
}

fn attach_and_pin_links(
    iface: &str,
    path: impl AsRef<Path>,
    attach_type: TcAttachType,
) -> Result<()> {
    let mut prog = SchedClassifier::from_pin(path)?;

    let link_id = prog.attach(iface, attach_type)?;

    let link = prog.take_link(link_id)?;
    let link: FdLink = link.try_into()?;
    let pin_path = pin_path(iface, attach_type);
    link.pin(pin_path)?;
    Ok(())
}

pub trait ReconcilePolicy {
    fn reconcile_policy(
        &self,
        pod_name: &str,
        pod_namespace: &str,
    ) -> std::result::Result<(), PolicyReconcileError>;
}

impl<P: PolicyControllerBpf + Send + Sync + 'static> ReconcilePolicy for Arc<Context<P>> {
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
