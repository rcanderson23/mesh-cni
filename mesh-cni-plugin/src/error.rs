use aya::EbpfError;
use aya::programs::ProgramError;
use semver::Version;
use thiserror::Error;

use crate::response::{CniErrorResponse, Response};

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Ebpf(String),

    #[error("incompatible version {0}")]
    IncompatibleVersion(Version),

    #[error("container unknown: {0}")]
    ContainerUnknown(String),

    #[error("unsupported field: {key}={value}")]
    UnsupportedField { key: String, value: String },

    #[error("invalid environment variables: {0}")]
    InvalidRequiredEnvVariables(String),

    #[error("invalid network config: {0}")]
    InvalidNetworkConfig(String),

    #[error("transient error: {0}")]
    Transient(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("missing previous result: {0}")]
    NoPreviousResult(String),

    #[error("cni must be chained after interfaces are created")]
    MissingInterfaces,

    #[error("{0}")]
    Tonic(#[from] tonic::Status),

    #[error("{0}")]
    TonicTransport(#[from] tonic::transport::Error),
}

impl Error {
    pub fn into_response(self, cni_version: Version) -> Response {
        let resp = match &self {
            Error::IncompatibleVersion(_) => CniErrorResponse {
                cni_version,
                code: 1,
                msg: "Incompatible Version".into(),
                details: self.to_string(),
            },
            Error::UnsupportedField { key: _, value: _ } => CniErrorResponse {
                cni_version,
                code: 2,
                msg: "Incompatible Version".into(),
                details: self.to_string(),
            },
            Error::ContainerUnknown(_) => CniErrorResponse {
                cni_version,
                code: 3,
                msg: "Incompatible Version".into(),
                details: self.to_string(),
            },
            Error::InvalidRequiredEnvVariables(_) => CniErrorResponse {
                cni_version,
                code: 4,
                msg: "Invalid Required Environment Variables".into(),
                details: self.to_string(),
            },
            Error::Io(_) => CniErrorResponse {
                cni_version,
                code: 5,
                msg: "I/O Error".into(),
                details: self.to_string(),
            },
            Error::Json(_) => CniErrorResponse {
                cni_version,
                code: 6,
                msg: "JSON Error".into(),
                details: self.to_string(),
            },
            Error::InvalidNetworkConfig(_) => CniErrorResponse {
                cni_version,
                code: 7,
                msg: "Invalid Network Config".into(),
                details: self.to_string(),
            },
            Error::Transient(_) => CniErrorResponse {
                cni_version,
                code: 11,
                msg: "Transient Error".into(),
                details: self.to_string(),
            },
            Error::Ebpf(_) => CniErrorResponse {
                cni_version,
                code: 101,
                msg: "EBPF Error".into(),
                details: self.to_string(),
            },
            Error::Parse(_) => CniErrorResponse {
                cni_version,
                code: 101,
                msg: "EBPF Error".into(),
                details: self.to_string(),
            },
            Error::NoPreviousResult(_) => CniErrorResponse {
                cni_version,
                code: 102,
                msg: "No Previous Result".into(),
                details: self.to_string(),
            },
            Error::MissingInterfaces => CniErrorResponse {
                cni_version,
                code: 103,
                msg: "No Interfaces".into(),
                details: self.to_string(),
            },
            Error::Tonic(_) => CniErrorResponse {
                cni_version,
                code: 104,
                msg: "Tonic".into(),
                details: self.to_string(),
            },
            Error::TonicTransport(_) => CniErrorResponse {
                cni_version,
                code: 105,
                msg: "Tonic Transport".into(),
                details: self.to_string(),
            },
        };
        Response::Error(resp)
    }
}

impl From<aya::EbpfError> for Error {
    fn from(err: EbpfError) -> Self {
        Self::Ebpf(err.to_string())
    }
}

impl From<aya::programs::ProgramError> for Error {
    fn from(err: ProgramError) -> Self {
        Self::Ebpf(err.to_string())
    }
}
