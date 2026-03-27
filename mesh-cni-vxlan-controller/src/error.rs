use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("operation error: {0}")]
    OpError(String),

    #[error("kube error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("kube utils error: {0}")]
    KubeUtils(#[from] mesh_cni_k8s_utils::Error),

    #[error("invalid ip network construction: {0}")]
    InvalidIpNetwork(#[from] ipnetwork::IpNetworkError),

    #[error("missing precondition: {0}")]
    MissingPrecondition(String),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
