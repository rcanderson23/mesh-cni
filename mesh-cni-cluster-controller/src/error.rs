use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("kube error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("yaml error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("other error: {0}")]
    Other(String),
}
