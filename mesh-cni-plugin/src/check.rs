use tracing::info;

use crate::config::Args;
use crate::response::Response;
use crate::types::Input;

pub fn check(_args: &Args, input: Input) -> Response {
    info!("check called, received input {:?}", input);
    Response::Check
}
