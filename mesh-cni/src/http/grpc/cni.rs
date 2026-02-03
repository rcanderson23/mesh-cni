use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::bail;
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
use tonic::{Code, Request, Response, Status};
use tracing::{error, info};

use crate::{
    Result,
    bpf::{BPF_MESH_LINKS_DIR, BPF_PROGRAM_INGRESS_TC},
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

pub trait ReconcilePolicy {
    fn reconcile_policy(&self, pod_name: &str, pod_namespace: &str) -> Result<()>;
}

impl<P: PolicyControllerBpf + Send + Sync + 'static> ReconcilePolicy for Arc<Context<P>> {
    fn reconcile_policy(&self, pod_name: &str, pod_namespace: &str) -> Result<()> {
        let Some(pod) = self
            .pod_store
            .get(&ObjectRef::new(pod_name).within(pod_namespace))
        else {
            bail!("faild to find pod in store");
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

        if identities.len() != 1 {
            bail!(
                "expected only one matching Identity, found {} for {}/{}",
                identities.len(),
                pod_name,
                pod_namespace,
            );
        };

        let identity = identities.first().unwrap().clone();

        reconcile_identity(identity, self.clone())?;
        Ok(())
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

        // TODO: consider a retrying 2 or 3 times here with a short backoff to handle
        // pods that generate new Identity CRs
        self.policy_reconciler
            .reconcile_policy(&request.pod_name, &request.pod_namespace)
            .map_err(|e| tonic::Status::new(Code::Internal, e.to_string()))?;

        let _ = tc::qdisc_add_clsact(&request.iface);
        info!("adding tc ingress progam to {}", &request.iface);
        attach_and_pin_links(
            &request.iface,
            BPF_PROGRAM_INGRESS_TC.path(),
            TcAttachType::Ingress,
        )
        .map_err(|e| tonic::Status::new(Code::Internal, e.to_string()))?;

        info!("adding tc egress progam to {}", &request.iface);
        if let Err(e) = attach_and_pin_links(
            &request.iface,
            BPF_PROGRAM_INGRESS_TC.path(),
            TcAttachType::Egress,
        ) {
            let ingress_path = pin_path(&request.iface, TcAttachType::Ingress);
            let egress_path = pin_path(&request.iface, TcAttachType::Egress);
            for path in [ingress_path, egress_path] {
                let Err(u) = unpin_path(path) else {
                    continue;
                };
                error!(%u, "failed to unpin path");
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
    let pin_path = match attach_type {
        TcAttachType::Ingress => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{}_ingress", MESH_INGRESS_LINK_PREFIX, iface)),
        TcAttachType::Egress => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{}_egress", MESH_INGRESS_LINK_PREFIX, iface)),
        TcAttachType::Custom(_) => PathBuf::from(BPF_MESH_LINKS_DIR)
            .join(format!("{}{}_custom", MESH_INGRESS_LINK_PREFIX, iface)),
    };
    link.pin(pin_path)?;
    Ok(())
}
