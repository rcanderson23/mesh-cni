use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{anyhow, bail};
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
use mesh_cni_policy_controller::{Context, PolicyDataplane, reconcile_identity};
use netns_rs::get_from_path;
use tokio::time::{Duration, sleep};
use tonic::{Code, Request, Response, Status};
use tracing::{error, info, warn};

use crate::{
    Result,
    bpf::{BPF_MESH_LINKS_DIR, BPF_PROGRAM_EGRESS_TC, BPF_PROGRAM_INGRESS_TC},
};

pub struct CniState<P: ReconcilePolicy + Send + Sync + 'static> {
    policy_reconciler: P,
    netns_dir: PathBuf,
}

const MESH_LINK_PREFIX: &str = "mesh_cni_link_";

impl<P: ReconcilePolicy + Send + Sync + 'static> CniState<P> {
    pub fn new(policy_reconciler: P, netns_dir: PathBuf) -> Self {
        Self {
            policy_reconciler,
            netns_dir,
        }
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
        // TODO: replace logging here with request middleware on the tonic server
        info!("received add request {:?}", request);
        let reply = add_pod(
            &self.policy_reconciler,
            request.into_inner(),
            self.netns_dir.clone(),
        )
        .await
        .map_err(|e| {
            error!(%e, "failed to add pod");
            Status::new(Code::Internal, e.to_string())
        })?;
        Ok(Response::new(reply))
    }

    async fn delete_pod(
        &self,
        request: Request<DeletePodRequest>,
    ) -> std::result::Result<Response<DeletePodReply>, Status> {
        let request = request.into_inner();
        info!("received delete request {:?}", request);

        for iface in [&request.iface, "lo"] {
            unpin_iface_paths(&request.container_id, iface)
                .map_err(|e| tonic::Status::new(Code::Internal, e.to_string()))?;
        }
        if let Some(netns) = request.net_namespace.as_deref() {
            let _netns_path = netns_path(self.netns_dir.clone(), netns).map_err(|e| {
                tonic::Status::new(Code::Internal, format!("failed to build netns path: {}", e))
            })?;
        }

        Ok(Response::new(DeletePodReply {}))
    }
}

async fn add_pod<P: ReconcilePolicy>(
    reconciler: &P,
    request: AddPodRequest,
    netns_dir: PathBuf,
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
            Err(err) => {
                bail!(err);
            }
        }
    }

    if let Some(e) = last_error {
        bail!(e);
    }

    let netns_path = netns_path(netns_dir, netns)?;

    let ns = get_from_path(netns_path)?;
    ns.run(|_| {
        let mut attached = Vec::new();
        for iface in [&request.iface, "lo"] {
            if let Err(e) = attach_for_iface(
                iface,
                &request.container_id,
                TcAttachType::Ingress,
                TcAttachType::Egress,
            ) {
                error!(%e, "failed to attach tc programs");
                for attached_iface in attached {
                    if let Err(u) = unpin_iface_paths(&request.container_id, attached_iface) {
                        error!(%u, "failed to unpin path");
                    };
                }
                return Err(e);
            }
            attached.push(iface);
        }
        Ok(())
    })??;

    Ok(AddPodReply::default())
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
    let _ = tc::qdisc_add_clsact(iface);

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
