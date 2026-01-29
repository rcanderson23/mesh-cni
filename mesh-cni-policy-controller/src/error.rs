use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("kube error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("failed to create store: {0}")]
    StoreCreation(String),

    #[error("timed out: {0}")]
    Timeout(String),

    #[error("utils error: {0}")]
    UtilsError(#[from] mesh_cni_k8s_utils::Error),

    #[error("bpf error: {0}")]
    BpfError(String),
}
