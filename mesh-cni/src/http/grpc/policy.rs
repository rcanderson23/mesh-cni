use mesh_cni_api::policy::v1::{
    ListPolicyReply, ListPolicyRequest, PolicySet,
    policy_server::{Policy as PolicyApi, PolicyServer},
};
use mesh_cni_ebpf_common::policy::{Action, PolicyKey, PolicyProtocol, PolicyValue};
use tonic::{Code, Request, Response, Status};
use tracing::info;

use crate::bpf::{SharedBpfMap, policy::PolicyState};

pub fn server<P>(state: PolicyState<P>) -> PolicyServer<Policy<P>>
where
    P: SharedBpfMap<Key = PolicyKey, Value = PolicyValue, KeyOutput = PolicyKey>,
{
    PolicyServer::new(Policy::new(state))
}

#[derive(Clone)]
pub struct Policy<P>
where
    P: SharedBpfMap<Key = PolicyKey, Value = PolicyValue, KeyOutput = PolicyKey>,
{
    state: PolicyState<P>,
}

impl<P> Policy<P>
where
    P: SharedBpfMap<Key = PolicyKey, Value = PolicyValue, KeyOutput = PolicyKey>,
{
    pub fn new(state: PolicyState<P>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl<P> PolicyApi for Policy<P>
where
    P: SharedBpfMap<Key = PolicyKey, Value = PolicyValue, KeyOutput = PolicyKey>,
{
    async fn list_policy(
        &self,
        _request: Request<ListPolicyRequest>,
    ) -> std::result::Result<Response<ListPolicyReply>, Status> {
        info!("policy request");
        let policy_state = self
            .state
            .state()
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let policies = policy_state
            .iter()
            .map(|(k, v)| PolicySet {
                src_id: k.src_id,
                dst_id: k.dst_id,
                dst_port: k.dst_port as u32,
                proto: PolicyProtocol::from(k.proto).to_string(),
                action: Action::from(v.action).to_string(),
            })
            .collect();

        Ok(Response::new(ListPolicyReply { policies }))
    }
}
