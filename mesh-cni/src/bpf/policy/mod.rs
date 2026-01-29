mod state;

use kube::Client;
use mesh_cni_ebpf_common::policy::{PolicyKey, PolicyValue};
pub use state::{PolicyBpfState, PolicyState};
use tokio_util::sync::CancellationToken;

use crate::{Result, bpf::SharedBpfMap};

pub async fn run<P>(
    kube_client: Client,
    policy_state: PolicyState<P>,
    cancel: CancellationToken,
) -> Result<()>
where
    P: SharedBpfMap<Key = PolicyKey, Value = PolicyValue, KeyOutput = PolicyKey>,
{
    let policy_controller =
        mesh_cni_policy_controller::start_policy_controllers(kube_client, policy_state, cancel);

    tokio::spawn(policy_controller);

    Ok(())
}
