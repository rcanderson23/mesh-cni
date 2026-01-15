use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("kube error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("k8s utils error: {0}")]
    K8sUtils(#[from] mesh_cni_k8s_utils::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn metric_label(&self) -> String {
        format!("{self:?}").to_lowercase()
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
