use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("kube error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("kube utils: {0}")]
    K8sUtils(#[from] mesh_cni_k8s_utils::Error),

    #[error("missing precondition: {0}")]
    ReconcileMissingPrecondition(String),

    #[error("bpf state error: {0}")]
    BpfState(String),

    #[error("{0}")]
    Other(String),

    #[error("Service resource is invalid")]
    InvalidResource,
}

impl Error {
    pub fn metric_label(&self) -> String {
        format!("{self:?}").to_lowercase()
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
