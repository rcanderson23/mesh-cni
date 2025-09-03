use std::{sync::Arc, time::Duration};

use k8s_openapi::api::core::v1::Service;
use kube::{ResourceExt, runtime::controller::Action};
use tracing::{error, info};

use crate::{Error, Result, kubernetes::controllers::service::state::State};

pub async fn reconcile(service: Arc<Service>, ctx: Arc<State>) -> Result<Action> {
    info!(
        "started reconciling Service {}/{}",
        service.metadata.namespace.as_ref().unwrap(),
        service.metadata.name.as_ref().unwrap(),
    );
    // if has multi-cluster service annotation create MeshEndpoints
    // otherwise return early
    let service_annotations = service.annotations();
    let Some(mcs_value) = service_annotations.get(super::MESH_SERVICE) else {
        return Ok(Action::await_change());
    };
    if mcs_value != "true" {
        return Ok(Action::await_change());
    }

    info!("creating mesh endoint");

    Ok(Action::await_change())
}

pub(crate) fn error_policy(service: Arc<Service>, error: &Error, _ctx: Arc<State>) -> Action {
    error!(
        "reconcile failed Service {}/{}: {:?}",
        service.metadata.namespace.as_ref().unwrap(),
        service.metadata.name.as_ref().unwrap(),
        error
    );
    // TODO: figure out exponential backoff
    Action::requeue(Duration::from_secs(30))
}
