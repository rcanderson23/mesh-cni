use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("kube error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("kube utils error: {0}")]
    KubeUtils(#[from] mesh_cni_k8s_utils::Error),

    #[error("encountered invalid resource")]
    InvalidResource,

    #[error("resource not found")]
    ResourceNotFound,

    #[error("invalid ip network construction: {0}")]
    InvalidIPNetwork(#[from] ipnetwork::IpNetworkError),

    #[error("update/delete error: {0}")]
    OpError(String),
}
