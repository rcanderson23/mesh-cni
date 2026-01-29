use std::sync::Arc;

use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::runtime::controller::Action;
use mesh_cni_crds::v1alpha1::identity::Identity;

use crate::{
    PolicyControllerBpf, PolicyControllerExt, Result, context::Context,
    controller::DEFAULT_REQUEUE_DURATION, selector::policy_selects_identity,
};

impl<P: PolicyControllerBpf> PolicyControllerExt<P> for Identity {
    async fn reconcile(&self, ctx: Arc<Context<P>>) -> Result<Action> {
        let policy_state = ctx.policy_store.state();
        let selected_netpols: Vec<&Arc<NetworkPolicy>> = policy_state
            .iter()
            .filter(|np| policy_selects_identity(np, self))
            .collect();

        Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
    }
}
