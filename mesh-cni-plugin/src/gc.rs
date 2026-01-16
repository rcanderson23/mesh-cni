use tracing::info;

use crate::{config::Args, response::Response, types::Input};

pub fn gc(_args: &Args, input: Input) -> Response {
    info!("gc called, received input {:?}", input);
    Response::Gc
}
