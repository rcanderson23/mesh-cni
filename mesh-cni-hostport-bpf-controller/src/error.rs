use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("kube error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("kube utils: {0}")]
    K8sUtils(#[from] mesh_cni_k8s_utils::Error),

    #[error("missing precondition: {0}")]
    MissingPrecondition(String),

    #[error("bpf state error: {0}")]
    BpfState(String),

    #[error("{0}")]
    Other(String),

    #[error("resource is invalid")]
    InvalidResource,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
