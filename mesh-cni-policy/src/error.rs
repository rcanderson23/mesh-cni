use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("kube error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("failed to create store: {0}")]
    StoreCreation(String),
}

impl From<mesh_cni_k8s_utils::Error> for Error {
    fn from(err: mesh_cni_k8s_utils::Error) -> Self {
        match err {
            mesh_cni_k8s_utils::Error::StoreCreation(msg) => Self::StoreCreation(msg),
            mesh_cni_k8s_utils::Error::KubeError(e) => Self::KubeError(e),
        }
    }
}
