use thiserror::Error;
use kube::runtime::finalizer;

#[derive(Error, Debug)]
pub enum Error {
    #[error("kube error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("yaml error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("other error: {0}")]
    Other(String),
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
