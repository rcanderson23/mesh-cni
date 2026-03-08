mod context;
mod controller;
mod error;
mod identity;
mod runtime;
pub mod selector;

pub use context::Context;
pub use error::Error;
pub use identity::inner_reconcile_policy_with_identity as reconcile_identity;
use mesh_cni_ebpf_common::policy::{
    CidrPolicyMapKey, PolicyIndexKey, PolicyRuleKey, PolicyValue, RulesetId,
};
pub use runtime::start_policy_controllers;

pub type Result<T> = std::result::Result<T, Error>;

pub trait PolicyIndexWriter {
    fn upsert_policy_index(&self, key: PolicyIndexKey, ruleset_id: RulesetId) -> Result<()>;
    fn remove_policy_index(&self, key: &PolicyIndexKey) -> Result<()>;
}

pub trait PolicyRulesetWriter {
    fn upsert_policy_rule(&self, key: PolicyRuleKey, value: PolicyValue) -> Result<()>;
    fn remove_policy_rule(&self, key: &PolicyRuleKey) -> Result<()>;
}

pub trait PolicyCidrWriter {
    fn upsert_cidr_index(&self, key: CidrPolicyMapKey, ruleset_id: RulesetId) -> Result<()>;
    fn remove_cidr_index(&self, key: &CidrPolicyMapKey) -> Result<()>;
}

pub trait PolicyReader {
    fn policy_index_state(&self) -> Result<ahash::HashMap<PolicyIndexKey, RulesetId>>;
    fn policy_ruleset_state(&self) -> Result<ahash::HashMap<PolicyRuleKey, PolicyValue>>;
    fn policy_cidr_index_state(&self) -> Result<ahash::HashMap<CidrPolicyMapKey, RulesetId>>;
}

pub trait PolicyDataplane:
    PolicyIndexWriter + PolicyRulesetWriter + PolicyCidrWriter + PolicyReader
{
}
impl<T> PolicyDataplane for T where
    T: PolicyIndexWriter + PolicyRulesetWriter + PolicyCidrWriter + PolicyReader
{
}
