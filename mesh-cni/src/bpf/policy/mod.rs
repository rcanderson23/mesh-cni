mod state;

use kube::Client;
use mesh_cni_ebpf_common::policy::{PolicyIndexKey, PolicyRuleKey, PolicyValue};
pub use state::{PolicyBpfState, PolicyIndexBpfState, PolicyRulesetBpfState, PolicyState};
use tokio_util::sync::CancellationToken;

use crate::{Result, bpf::SharedBpfMap};

pub async fn run<PI, PR>(
    kube_client: Client,
    policy_state: PolicyState<PI, PR>,
    cancel: CancellationToken,
) -> Result<()>
where
    PI: SharedBpfMap<Key = PolicyIndexKey, Value = u32, KeyOutput = PolicyIndexKey>,
    PR: SharedBpfMap<Key = PolicyRuleKey, Value = PolicyValue, KeyOutput = PolicyRuleKey>,
{
    let policy_controller =
        mesh_cni_policy_controller::start_policy_controllers(kube_client, policy_state, cancel);

    tokio::spawn(policy_controller);

    Ok(())
}
