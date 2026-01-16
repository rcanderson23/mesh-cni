use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("kube error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("yaml error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("other error: {0}")]
    Other(String),

    #[error("timeout")]
    Timeout,

    #[error("utils error: {0}")]
    UtilsError(#[from] mesh_cni_k8s_utils::Error),

    #[error("invalid resource reconciled")]
    InvalidResource,

    #[error("resource not found in store")]
    ResourceNotFound,

    #[error("failed to convert spec to bytes")]
    HashConversionFailure,

    #[error("failed to send resource on channel")]
    SendFailure,
}
