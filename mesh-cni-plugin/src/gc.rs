use tracing::info;

use crate::config::Args;
use crate::response::Response;
use crate::types::Input;

pub fn gc(_args: &Args, input: Input) -> Response {
    info!("gc called, received input {:?}", input);
    Response::Gc
}
