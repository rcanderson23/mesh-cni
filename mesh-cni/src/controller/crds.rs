use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Patch, PatchParams};
use kube::runtime::conditions;
use kube::runtime::wait::await_condition;
use kube::{Api, CustomResourceExt};
use tracing::{error, info};

use crate::kubernetes::crds::meshendpoint::NAME_GROUP_MESHENDPOINT;
use crate::{Error, Result};

pub async fn apply_crds(client: kube::Client) -> Result<()> {
    let crds: Api<CustomResourceDefinition> = Api::all(client);
    let ssaply = PatchParams::apply("mesh_cni").force();
    crds.patch(
        NAME_GROUP_MESHENDPOINT,
        &ssaply,
        &Patch::Apply(&crate::kubernetes::crds::meshendpoint::v1alpha1::MeshEndpoint::crd()),
    )
    .await?;
    let established = await_condition(
        crds,
        NAME_GROUP_MESHENDPOINT,
        conditions::is_crd_established(),
    );
    // TODO: FIXME
    match tokio::time::timeout(std::time::Duration::from_secs(5), established).await {
        Ok(o) => o?,

        Err(e) => return Err(Error::Other(e.to_string())),
    };
    info!("applied MeshEndpoint CRD");
    Ok(())
}

fn exit(task: &str, out: Result<()>) {
    match out {
        Ok(_) => {
            info!("{task} exited")
        }
        Err(e) => {
            error!("{task} failed with error: {e}")
        }
    }
}
