use serde::Deserialize;
use tracing::info;

use crate::response::Response;
use crate::types::Input;
use crate::{CNI_VERSION, Error};
use crate::{config::Args, response::Success};

pub fn delete(_args: &Args, input: Input) -> Response {
    info!("delete called, received input {:?}", input);
    let Some(prev) = input.previous_result else {
        return Error::NoPreviousResult("no previous result found".into())
            .into_response(CNI_VERSION);
    };

    let prev = match Success::deserialize(prev) {
        Ok(prev) => prev,
        Err(e) => return Error::from(e).into_response(CNI_VERSION),
    };

    Response::Success(Success {
        cni_version: prev.cni_version,
        interfaces: prev.interfaces,
        ips: prev.ips,
        routes: prev.routes,
        dns: prev.dns,
        custom: prev.custom,
    })
}
