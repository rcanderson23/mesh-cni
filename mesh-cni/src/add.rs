use serde::Deserialize;
use tracing::{error, info};

use crate::response::Response;
use crate::types::Input;
use crate::{CNI_VERSION, Error};
use crate::{config::Args, response::Success};

pub fn add(_args: &Args, input: Input) -> Response {
    info!("add called, received input {:?}", input);
    let Some(prev) = input.previous_result else {
        return Error::NoPreviousResult(
            "no previous result found, this CNI must be chained".into(),
        )
        .into_response(CNI_VERSION);
    };

    let prev = match Success::deserialize(prev) {
        Ok(prev) => prev,
        Err(e) => {
            error!(%e, "failed to deserialize previous results");
            return Error::from(e).into_response(CNI_VERSION);
        }
    };

    if prev.interfaces.is_empty() {
        error!("previous response is missing interfaces");
        return Error::MissingInterfaces.into_response(CNI_VERSION);
    }
    let success = Success {
        cni_version: prev.cni_version,
        interfaces: prev.interfaces,
        ips: prev.ips,
        routes: prev.routes,
        dns: prev.dns,
        custom: prev.custom,
    };
    info!("add response {:?}", success);
    Response::Success(success)
}
