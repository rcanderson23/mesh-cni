use serde_json::Value;
use std::io::Write;
use std::{collections::HashMap, process::ExitCode};

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::{
    Result,
    types::{Dns, Interface, Ip, Route},
};

#[derive(Serialize, Deserialize)]
pub enum Response {
    Success(Success),
    Error(CniErrorResponse),
    Version(VersionResponse),
    Gc,
    Check,
    Status,
}

impl Response {
    pub fn write_out(self) -> ExitCode {
        let (out, code) = match &self {
            Response::Success(success) => match serde_json::to_vec(&success) {
                Ok(out) => (out, ExitCode::SUCCESS),
                Err(e) => (e.to_string().into_bytes(), ExitCode::FAILURE),
            },
            Response::Error(cni_error_response) => match serde_json::to_vec(&cni_error_response) {
                Ok(out) => (out, ExitCode::SUCCESS),
                Err(e) => (e.to_string().into_bytes(), ExitCode::FAILURE),
            },
            Response::Version(version_response) => match serde_json::to_vec(&version_response) {
                Ok(out) => (out, ExitCode::SUCCESS),
                Err(e) => (e.to_string().into_bytes(), ExitCode::FAILURE),
            },
            Response::Check => (vec![], ExitCode::SUCCESS),
            Response::Gc => (vec![], ExitCode::SUCCESS),
            Response::Status => (vec![], ExitCode::SUCCESS),
        };
        std::io::stdout()
            .write_all(&out)
            .expect("failed to write out response to stdout");
        code
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Success {
    #[serde(
        serialize_with = "crate::serialize_to_string",
        deserialize_with = "crate::deserialize_from_str"
    )]
    pub cni_version: Version,

    #[serde(default)]
    pub interfaces: Vec<mesh_cni_api::cni::v1::Interface>,

    #[serde(default)]
    pub ips: Vec<mesh_cni_api::cni::v1::Ip>,

    #[serde(default)]
    pub routes: Vec<mesh_cni_api::cni::v1::Route>,

    #[serde(default)]
    pub dns: Option<mesh_cni_api::cni::v1::Dns>,

    #[serde(flatten)]
    pub custom: HashMap<String, Value>,
}

impl Success {
    pub fn into_response(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VersionResponse {
    #[serde(
        serialize_with = "crate::serialize_to_string",
        deserialize_with = "crate::deserialize_from_str"
    )]
    pub cni_version: Version,
    #[serde(
        serialize_with = "crate::serialize_to_string_slice",
        deserialize_with = "crate::deserialize_from_str_vec"
    )]
    pub supported_versions: Vec<Version>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CniErrorResponse {
    #[serde(
        serialize_with = "crate::serialize_to_string",
        deserialize_with = "crate::deserialize_from_str"
    )]
    pub cni_version: Version,
    pub code: u32,
    pub msg: String,
    pub details: String,
}
