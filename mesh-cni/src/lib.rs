pub mod agent;
pub mod cni;
pub mod config;
pub mod controller;
pub mod http;
pub mod kubernetes;
pub mod metrics;

use aya::EbpfError;
use aya::pin::PinError;
use aya::programs::ProgramError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    EbpfError(String),

    #[error("{0}")]
    EbpfProgramError(String),

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("conversion error: {0}")]
    ConversionError(String),

    #[error("CryptoError: {0}")]
    CryptoError(String),

    #[error("failed to create store: {0}")]
    StoreCreation(String),

    #[error("failed to convert Pod to IpIdentity")]
    ConvertPodIpIdentity,

    #[error("kube error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("addr parse error: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error("kube stream failed")]
    KubeStreamFailed,

    #[error("unable to send event due to channel error")]
    ChannelError,

    #[error("map error: {0}")]
    MapError(#[from] aya::maps::MapError),

    #[error(transparent)]
    JsonConversion(#[from] serde_json::Error),

    // TODO: improve error
    #[error("network namespace provided is invalid: {0}")]
    InvalidSandbox(String),

    #[error("network namespace provided is invalid")]
    NetNs(#[from] netns_rs::Error),

    #[error("{0}")]
    Other(String),

    #[error("map {name} not found")]
    MapNotFound { name: String },

    #[error("{0}")]
    TonicTransport(#[from] tonic::transport::Error),

    #[error("failed to pin program: {0}")]
    PinError(#[from] PinError),

    #[error("task failed: {0}")]
    Task(String),

    #[error("failed to create config from kubeconfig: {0}")]
    KubeConfig(#[from] kube::config::KubeconfigError),

    #[error("failed to parse clusters config: {0}")]
    YamlConversion(#[from] serde_yaml::Error),

    #[error("failed to reconcile resource: {0}")]
    ReconcileError(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl From<aya::EbpfError> for Error {
    fn from(err: EbpfError) -> Self {
        Self::EbpfError(err.to_string())
    }
}

impl From<aya::programs::ProgramError> for Error {
    fn from(err: ProgramError) -> Self {
        Self::EbpfError(err.to_string())
    }
}
