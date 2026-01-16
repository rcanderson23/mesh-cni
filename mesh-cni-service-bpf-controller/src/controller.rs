use std::{fmt::Debug, sync::Arc, time::Duration};

use ahash::HashMap;
use k8s_openapi::api::{core::v1::Service, discovery::v1::EndpointSlice};
use kube::{
    ResourceExt,
    core::{Expression, Selector, SelectorExt},
    runtime::{controller::Action, reflector::ObjectRef},
};
use mesh_cni_crds::v1alpha1::meshendpoint::{MeshEndpoint, generate_mesh_endpoint_spec};
use mesh_cni_ebpf_common::service::{EndpointValue, ServiceKey};
use serde::de::DeserializeOwned;
use tracing::{error, info};

use crate::{Context, Error, MESH_SERVICE, Result, ServiceBpfState};

pub const SERVICE_OWNER_LABEL: &str = "kubernetes.io/service-name";

pub trait MeshControllerExt<B>
where
    B: ServiceBpfState + Clone + Send + Sync + 'static,
{
    fn generate_service_pairs(&self, state: &Context<B>)
    -> HashMap<ServiceKey, Vec<EndpointValue>>;
    fn is_current(&self, state: &Context<B>) -> bool;
}

impl<B> MeshControllerExt<B> for MeshEndpoint
where
    B: ServiceBpfState + Clone + Send + Sync + 'static,
{
    fn generate_service_pairs(
        &self,
        _state: &Context<B>,
    ) -> HashMap<ServiceKey, Vec<EndpointValue>> {
        self.generate_bpf_service_endpoints()
    }
    fn is_current(&self, state: &Context<B>) -> bool {
        let Some(cached) = state
            .mesh_endpoint_state
            .get(&ObjectRef::new(&self.name_any()).within(&self.namespace().unwrap_or_default()))
        else {
            return false;
        };
        cached.spec == self.spec
    }
}

impl<B> MeshControllerExt<B> for Service
where
    B: ServiceBpfState + Clone + Send + Sync + 'static,
{
    fn generate_service_pairs(
        &self,
        state: &Context<B>,
    ) -> HashMap<ServiceKey, Vec<EndpointValue>> {
        let spec = generate_mesh_endpoint_spec(&state.endpoint_slice_state, self);
        let mep = MeshEndpoint::new("dummy", spec);
        mep.generate_bpf_service_endpoints()
    }
    fn is_current(&self, state: &Context<B>) -> bool {
        let Some(cached) = state
            .service_state
            .get(&ObjectRef::new(&self.name_any()).within(&self.namespace().unwrap_or_default()))
        else {
            return false;
        };
        cached.spec == self.spec
    }
}

impl<B> MeshControllerExt<B> for EndpointSlice
where
    B: ServiceBpfState + Clone + Send + Sync + 'static,
{
    fn generate_service_pairs(
        &self,
        state: &Context<B>,
    ) -> HashMap<ServiceKey, Vec<EndpointValue>> {
        let selector: Selector =
            Expression::Equal(SERVICE_OWNER_LABEL.into(), self.name_any()).into();
        let service: Vec<Arc<Service>> = state
            .service_state
            .state()
            .iter()
            .filter(|s| self.namespace() == s.namespace() && selector.matches(s.labels()))
            .cloned()
            .collect();
        let Some(service) = service.first() else {
            return HashMap::default();
        };
        let spec = generate_mesh_endpoint_spec(&state.endpoint_slice_state, service);
        let mep = MeshEndpoint::new("dummy", spec);
        mep.generate_bpf_service_endpoints()
    }
    fn is_current(&self, state: &Context<B>) -> bool {
        let Some(cached) = state
            .endpoint_slice_state
            .get(&ObjectRef::new(&self.name_any()).within(&self.namespace().unwrap_or_default()))
        else {
            return false;
        };
        cached.address_type == self.address_type
            && cached.endpoints == self.endpoints
            && cached.ports == self.ports
    }
}

pub async fn reconcile<K, B>(k: Arc<K>, ctx: Arc<Context<B>>) -> Result<Action>
where
    K: MeshControllerExt<B>,
    K: ResourceExt<DynamicType = ()>,
    K: DeserializeOwned + Clone + Sync + Debug + Send + 'static,
    B: ServiceBpfState + Clone + Send + Sync + 'static,
{
    let ns = k
        .namespace()
        .ok_or_else(|| Error::ReconcileMissingPrecondition("missing namespace".into()))?;
    let ns_name = format!("{}/{}", ns, k.name_any());
    let selector: Selector = Expression::Equal(MESH_SERVICE.into(), "true".into()).into();
    if selector.matches(k.labels()) {
        return Ok(Action::await_change());
    }
    info!("started reconciling {} {}", K::kind(&()), ns_name);

    if !k.is_current(&ctx) {
        info!(
            "requeuing {} {} because it is not current with cache",
            K::kind(&()),
            ns_name
        );
        return Ok(Action::requeue(Duration::from_millis(200)));
    }
    let service_pairs = k.generate_service_pairs(&ctx);

    if k.meta().deletion_timestamp.is_some() {
        for key in service_pairs.keys() {
            ctx.service_bpf_state.remove(key)?;
        }
    }
    for (key, val) in service_pairs.iter() {
        ctx.service_bpf_state.update(*key, val.to_owned())?;
    }

    Ok(Action::await_change())
}

pub fn error_policy<K, B>(_service: Arc<K>, error: &Error, _ctx: Arc<Context<B>>) -> Action
where
    K: MeshControllerExt<B>,
    K: ResourceExt<DynamicType = ()>,
    K: DeserializeOwned + Clone + Sync + Debug + Send + 'static,
    B: ServiceBpfState + Clone + Send + Sync + 'static,
{
    error!("error occurred: {}", error);
    Action::requeue(Duration::from_secs(5 * 60))
}
