use tracing::info;

use crate::config::Args;
use crate::response::{Response, VersionResponse};
use crate::types::Input;
use crate::{CNI_VERSION, SUPPORTED_CNI_VERSION};

pub fn gc(_args: &Args, input: Input) -> Response {
    info!("gc called, received input {:?}", input);
    Response::Version(VersionResponse {
        cni_version: CNI_VERSION,
        supported_versions: SUPPORTED_CNI_VERSION.to_vec(),
    })
}
