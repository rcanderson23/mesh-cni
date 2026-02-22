use kube::runtime::finalizer;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("kube error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("yaml error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("kube utils error: {0}")]
    KubeUtils(#[from] mesh_cni_k8s_utils::Error),

    #[error("other error: {0}")]
    Other(String),

    #[error("resource {kind}/{name} not found")]
    ResourceNotFound { kind: String, name: String },

    #[error("kubeconfig not found in secret {name} at key {key}")]
    KubeconfigNotFound { name: String, key: String },

    #[error("failed to start controller {0}")]
    StartUpFailed(String),

    #[error("child controller still running")]
    ControllerRunning,

    #[error("resource is not valid")]
    InvalidResource,

    #[error("cluster owned resources still remaining")]
    CleanupPending,

    #[error("timeout on condition")]
    Timeout,
}

impl From<finalizer::Error<Error>> for Error {
    fn from(err: finalizer::Error<Error>) -> Self {
        match err {
            finalizer::Error::ApplyFailed(e) | finalizer::Error::CleanupFailed(e) => e,
            finalizer::Error::AddFinalizer(e) | finalizer::Error::RemoveFinalizer(e) => {
                Error::KubeError(e)
            }
            finalizer::Error::UnnamedObject => Error::Other("object has no name".into()),
            finalizer::Error::InvalidFinalizer => Error::Other("invalid finalizer".into()),
        }
    }
}
