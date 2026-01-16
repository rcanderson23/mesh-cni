use tracing::info;

use crate::{config::Args, response::Response, types::Input};

pub fn check(_args: &Args, input: Input) -> Response {
    info!("check called, received input {:?}", input);
    Response::Check
}
