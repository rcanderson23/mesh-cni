use tracing::info;

use crate::{
    CNI_VERSION, SUPPORTED_CNI_VERSION,
    config::Args,
    response::{Response, VersionResponse},
    types::Input,
};

pub fn gc(_args: &Args, input: Input) -> Response {
    info!("gc called, received input {:?}", input);
    Response::Version(VersionResponse {
        cni_version: CNI_VERSION,
        supported_versions: SUPPORTED_CNI_VERSION.to_vec(),
    })
}
