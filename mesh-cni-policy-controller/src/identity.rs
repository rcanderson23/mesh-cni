use std::sync::Arc;

use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::runtime::controller::Action;
use mesh_cni_crds::v1alpha1::identity::Identity;
use mesh_cni_ebpf_common::policy::{
    ANY_ID, PolicyDirection, PolicyIndexKey,
};

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

        if selected_netpols.is_empty() {
            ctx.policy_bpf_state.update_index(
                PolicyIndexKey {
                    src_id: self.spec.id,
                    dst_id: ANY_ID,
                    direction: PolicyDirection::Any as u8,
                    _pad: [0; 3],
                },
                0,
            )?;
            return Ok(Action::requeue(DEFAULT_REQUEUE_DURATION));
        }

        Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
    }
}
