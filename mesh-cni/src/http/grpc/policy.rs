use mesh_cni_api::policy::v1::{
    ListPolicyReply, ListPolicyRequest, PolicySet,
    policy_server::{Policy as PolicyApi, PolicyServer},
};
use mesh_cni_ebpf_common::policy::{
    Action, PolicyDirection, PolicyIndexKey, PolicyProtocol, PolicyRuleKey, PolicyValue,
    RULESET_NONE,
};
use tonic::{Code, Request, Response, Status};
use tracing::info;

use crate::bpf::{SharedBpfMap, policy::PolicyState};

pub fn server<PI, PR>(state: PolicyState<PI, PR>) -> PolicyServer<Policy<PI, PR>>
where
    PI: SharedBpfMap<Key = PolicyIndexKey, Value = u32, KeyOutput = PolicyIndexKey>,
    PR: SharedBpfMap<Key = PolicyRuleKey, Value = PolicyValue, KeyOutput = PolicyRuleKey>,
{
    PolicyServer::new(Policy::new(state))
}

#[derive(Clone)]
pub struct Policy<PI, PR>
where
    PI: SharedBpfMap<Key = PolicyIndexKey, Value = u32, KeyOutput = PolicyIndexKey>,
    PR: SharedBpfMap<Key = PolicyRuleKey, Value = PolicyValue, KeyOutput = PolicyRuleKey>,
{
    state: PolicyState<PI, PR>,
}

impl<PI, PR> Policy<PI, PR>
where
    PI: SharedBpfMap<Key = PolicyIndexKey, Value = u32, KeyOutput = PolicyIndexKey>,
    PR: SharedBpfMap<Key = PolicyRuleKey, Value = PolicyValue, KeyOutput = PolicyRuleKey>,
{
    pub fn new(state: PolicyState<PI, PR>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl<PI, PR> PolicyApi for Policy<PI, PR>
where
    PI: SharedBpfMap<Key = PolicyIndexKey, Value = u32, KeyOutput = PolicyIndexKey>,
    PR: SharedBpfMap<Key = PolicyRuleKey, Value = PolicyValue, KeyOutput = PolicyRuleKey>,
{
    async fn list_policy(
        &self,
        _request: Request<ListPolicyRequest>,
    ) -> std::result::Result<Response<ListPolicyReply>, Status> {
        info!("policy request");
        let index_state = self
            .state
            .index_state()
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let ruleset_state = self
            .state
            .ruleset_state()
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;

        let mut rules_by_id: ahash::HashMap<u32, Vec<(PolicyRuleKey, PolicyValue)>> =
            ahash::HashMap::default();
        for (k, v) in ruleset_state {
            rules_by_id.entry(k.ruleset_id).or_default().push((k, v));
        }

        let mut policies = Vec::new();
        for (idx_key, ruleset_id) in index_state {
            if ruleset_id == RULESET_NONE {
                continue;
            }
            let Some(rules) = rules_by_id.get(&ruleset_id) else {
                continue;
            };
            for (rule_key, rule_value) in rules {
                policies.push(PolicySet {
                    src_id: idx_key.src_id,
                    dst_id: idx_key.dst_id,
                    dst_port: rule_key.port as u32,
                    proto: PolicyProtocol::from(rule_key.proto).to_string(),
                    direction: PolicyDirection::from(idx_key.direction).to_string(),
                    action: Action::from(rule_value.action).to_string(),
                });
            }
        }

        Ok(Response::new(ListPolicyReply { policies }))
    }
}
