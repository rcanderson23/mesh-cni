use std::{fmt::Debug, sync::Arc, time::Duration};

use ahash::HashMap;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::core::{Expression, Selector, SelectorExt};
use kube::runtime::reflector::ObjectRef;
use kube::{ResourceExt, runtime::controller::Action};
use serde::de::DeserializeOwned;
use tracing::{Span, error, field, info};

use crate::bpf::service::ServiceEndpointBpfMap;
use crate::kubernetes::controllers::bpf_service::MESH_SERVICE;
use crate::kubernetes::controllers::metrics;
use crate::kubernetes::crds::meshendpoint::v1alpha1::{MeshEndpoint, generate_mesh_endpoint_spec};
use crate::kubernetes::state::MultiClusterStore;
use crate::{Error, Result, kubernetes::controllers::bpf_service::context::Context};

use mesh_cni_ebpf_common::service::{
    EndpointValue, EndpointValueV4, EndpointValueV6, ServiceKey, ServiceKeyV4, ServiceKeyV6,
};

pub const SERVICE_OWNER_LABEL: &str = "kubernetes.io/service-name";
// const MANANGER: &str = "service-meshendpoint-controller";

pub trait MeshControllerExt<SE4, SE6>
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
{
    fn generate_service_pairs(
        &self,
        state: &Context<SE4, SE6>,
    ) -> HashMap<ServiceKey, Vec<EndpointValue>>;
    fn is_current(&self, state: &Context<SE4, SE6>) -> bool;
}

impl<SE4, SE6> MeshControllerExt<SE4, SE6> for MeshEndpoint
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
{
    fn generate_service_pairs(
        &self,
        _state: &Context<SE4, SE6>,
    ) -> HashMap<ServiceKey, Vec<EndpointValue>> {
        self.generate_bpf_service_endpoints()
    }
    fn is_current(&self, state: &Context<SE4, SE6>) -> bool {
        let Some(cached) = state
            .mesh_endpoint_state
            .get(&ObjectRef::new(&self.name_any()).within(&self.namespace().unwrap_or_default()))
        else {
            return false;
        };
        cached.spec == self.spec
    }
}

impl<SE4, SE6> MeshControllerExt<SE4, SE6> for Service
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
{
    fn generate_service_pairs(
        &self,
        state: &Context<SE4, SE6>,
    ) -> HashMap<ServiceKey, Vec<EndpointValue>> {
        let spec = generate_mesh_endpoint_spec(&state.endpoint_slice_state, self);
        let mep = MeshEndpoint::new("dummy", spec);
        mep.generate_bpf_service_endpoints()
    }
    fn is_current(&self, state: &Context<SE4, SE6>) -> bool {
        let Some(cached) = state
            .service_state
            .get(&ObjectRef::new(&self.name_any()).within(&self.namespace().unwrap_or_default()))
        else {
            return false;
        };
        cached.spec == self.spec
    }
}

// This is a little spooky as this state could potentially be multi or single cluster and
// we are relying on it being the owned cluster.
// TODO: add a single cluster store trait
impl<SE4, SE6> MeshControllerExt<SE4, SE6> for EndpointSlice
where
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
{
    fn generate_service_pairs(
        &self,
        state: &Context<SE4, SE6>,
    ) -> HashMap<ServiceKey, Vec<EndpointValue>> {
        let service = state.service_state.get_all_by_namespace_label(
            self.namespace().as_deref(),
            &Expression::Equal(SERVICE_OWNER_LABEL.into(), self.name_any()).into(),
        );
        let Some(service) = service.first() else {
            return HashMap::default();
        };
        let spec = generate_mesh_endpoint_spec(&state.endpoint_slice_state, service);
        let mep = MeshEndpoint::new("dummy", spec);
        mep.generate_bpf_service_endpoints()
    }
    fn is_current(&self, state: &Context<SE4, SE6>) -> bool {
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

pub async fn reconcile<K, SE4, SE6>(k: Arc<K>, ctx: Arc<Context<SE4, SE6>>) -> Result<Action>
where
    K: MeshControllerExt<SE4, SE6>,
    K: ResourceExt<DynamicType = ()>,
    K: DeserializeOwned + Clone + Sync + Debug + Send + 'static,
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
{
    let trace_id = metrics::get_trace_id();
    if trace_id != opentelemetry::trace::TraceId::INVALID {
        Span::current().record("trace_id", field::display(&trace_id));
    }
    let _timer = ctx.metrics.count_and_measure(k.as_ref(), &trace_id);
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

    // TODO: add finalizer to service so that deletes on the map must succeed
    // so that keys/values are not orphaned
    // This also isn't quite right as removal of a meshendpoint should
    // fall back to the service
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

// TODO: fix error coditions an{d potentially make generic for all controllers
pub fn error_policy<K, SE4, SE6>(
    service: Arc<K>,
    error: &Error,
    ctx: Arc<Context<SE4, SE6>>,
) -> Action
where
    K: MeshControllerExt<SE4, SE6>,
    K: ResourceExt<DynamicType = ()>,
    K: DeserializeOwned + Clone + Sync + Debug + Send + 'static,
    SE4: ServiceEndpointBpfMap<SKey = ServiceKeyV4, EValue = EndpointValueV4>,
    SE6: ServiceEndpointBpfMap<SKey = ServiceKeyV6, EValue = EndpointValueV6>,
{
    error!("error occurred: {}", error);
    ctx.metrics.count_failure(service.as_ref(), error);
    Action::requeue(Duration::from_secs(5 * 60))
}
