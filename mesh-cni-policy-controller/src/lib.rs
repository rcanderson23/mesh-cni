mod context;
mod controller;
mod error;
mod identity;
mod runtime;
pub mod selector;

pub use context::Context;
pub use error::Error;
pub use identity::inner_reconcile_policy_with_identity as reconcile_identity;
use mesh_cni_ebpf_common::policy::{PolicyIndexKey, PolicyRuleKey, PolicyValue};
pub use runtime::start_policy_controllers;

pub type Result<T> = std::result::Result<T, Error>;

pub trait PolicyControllerBpf {
    fn update_index(&self, key: PolicyIndexKey, ruleset_id: u32) -> Result<()>;
    fn delete_index(&self, key: &PolicyIndexKey) -> Result<()>;
    fn update_rule(&self, key: PolicyRuleKey, value: PolicyValue) -> Result<()>;
    fn delete_rule(&self, key: &PolicyRuleKey) -> Result<()>;
    fn index_state(&self) -> Result<ahash::HashMap<PolicyIndexKey, u32>>;
    fn ruleset_state(&self) -> Result<ahash::HashMap<PolicyRuleKey, PolicyValue>>;
}
