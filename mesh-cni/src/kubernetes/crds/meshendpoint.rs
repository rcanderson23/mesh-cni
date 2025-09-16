use kube::CustomResource;
use kube::KubeSchema;
use serde::{Deserialize, Serialize};

pub const NAME_GROUP_MESHENDPOINT: &str = "meshendpoints.mesh-cni.dev";
pub mod v1alpha1 {

    use std::net::IpAddr;
    use std::sync::Arc;

    use ahash::HashMap;
    use k8s_openapi::api::core::v1::Service;
    use k8s_openapi::api::discovery::v1::{EndpointConditions, EndpointSlice};
    use kube::ResourceExt;
    use kube::core::Expression;
    use mesh_cni_common::KubeProtocol;
    use mesh_cni_common::service::{
        EndpointValue, EndpointValueV4, EndpointValueV6, ServiceKey, ServiceKeyV4, ServiceKeyV6,
    };
    use tracing::warn;

    use crate::kubernetes::controllers::utils::kube_proto_from_str;
    use crate::kubernetes::service::SERVICE_OWNER_LABEL;
    use crate::kubernetes::state::MultiClusterStore;

    use super::*;

    #[derive(
        CustomResource, KubeSchema, Serialize, Deserialize, Default, PartialEq, Eq, Clone, Debug,
    )]
    #[kube(
        group = "mesh-cni.dev",
        version = "v1alpha1",
        kind = "MeshEndpoint",
        derive = "Default",
        derive = "PartialEq",
        namespaced
    )]
    pub struct MeshEndpointSpec {
        pub service_ips: Vec<IpAddr>,
        pub backend_port_mappings: Vec<BackendPortMapping>,
    }

    #[derive(KubeSchema, Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
    pub struct BackendPortMapping {
        pub ip: IpAddr,
        pub service_port: u16,
        pub backend_port: u16,
        pub protocol: String,
    }

    impl MeshEndpoint {
        pub fn generate_bpf_service_endpoints(&self) -> HashMap<ServiceKey, Vec<EndpointValue>> {
            let mut result: HashMap<ServiceKey, Vec<EndpointValue>> = HashMap::default();
            for service_ip in &self.spec.service_ips {
                for mapping in &self.spec.backend_port_mappings {
                    let protocol = kube_proto_from_str(&Some(mapping.protocol.clone()));

                    let (service_key, endpoint_value) = match (service_ip, mapping.ip) {
                        (IpAddr::V4(svc_v4), IpAddr::V4(ep_v4)) => (
                            ServiceKey::V4(ServiceKeyV4 {
                                ip: svc_v4.to_bits(),
                                port: mapping.service_port,
                                protocol,
                            }),
                            EndpointValue::V4(EndpointValueV4 {
                                ip: ep_v4.to_bits(),
                                port: mapping.backend_port,
                                _protocol: protocol,
                            }),
                        ),
                        (IpAddr::V6(svc_v6), IpAddr::V6(ep_v6)) => (
                            ServiceKey::V6(ServiceKeyV6 {
                                ip: svc_v6.to_bits(),
                                port: mapping.service_port,
                                protocol,
                            }),
                            EndpointValue::V6(EndpointValueV6 {
                                ip: ep_v6.to_bits(),
                                port: mapping.backend_port,
                                _protocol: protocol,
                            }),
                        ),
                        _ => {
                            continue;
                        }
                    };

                    if let Some(eps) = result.get_mut(&service_key) {
                        eps.push(endpoint_value);
                    } else {
                        result.insert(service_key, vec![endpoint_value]);
                    }
                }
            }
            result
        }
    }
    pub fn generate_mesh_endpoint_spec<T: MultiClusterStore<EndpointSlice>>(
        store: &T,
        service: &Service,
    ) -> MeshEndpointSpec {
        let service_ips = service_ips_from_service(service);
        let service_names_ports_protocols = service_names_ports_protocols(service);

        let slices = endpoint_slices_owned_by_service(store, service);

        let mut backend_port_mappings = Vec::new();

        for slice in &slices {
            let backend_ips = backend_ips_from_ep_slice(slice);
            for ip in backend_ips {
                for (name, service_port, protocol) in &service_names_ports_protocols {
                    let Some(backend_port) = backend_port_from_ep_slice(slice, name, *protocol)
                    else {
                        continue;
                    };

                    backend_port_mappings.push(BackendPortMapping {
                        ip,
                        service_port: *service_port,
                        backend_port,
                        protocol: protocol.to_string(),
                    });
                }
            }
        }

        MeshEndpointSpec {
            service_ips,
            backend_port_mappings,
        }
    }
    fn endpoint_slices_owned_by_service<T: MultiClusterStore<EndpointSlice>>(
        store: &T,
        service: &Service,
    ) -> Vec<Arc<EndpointSlice>> {
        let selector = Expression::Equal(SERVICE_OWNER_LABEL.into(), service.name_any()).into();
        // Service is namespaced
        store.get_all_by_namespace_label(Some(&service.namespace().unwrap_or_default()), &selector)
    }

    fn endpoint_ready(ep_cond: &EndpointConditions) -> bool {
        (ep_cond.ready == Some(true) || ep_cond.ready.is_none())
            && (ep_cond.terminating != Some(true))
    }

    fn service_ips_from_service(service: &Service) -> Vec<IpAddr> {
        let mut result = Vec::new();
        if let Some(spec) = &service.spec
            && let Some(ips) = &spec.cluster_ips
        {
            for ip in ips {
                if let Ok(ip) = ip.parse() {
                    result.push(ip);
                } else {
                    warn!(
                        "failed to parse ClusterIP {} in Service {}/{}",
                        ip,
                        service.namespace().unwrap_or_default(),
                        service.name_any()
                    )
                }
            }
        }
        result
    }

    fn backend_ips_from_ep_slice(slice: &EndpointSlice) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        for endpoint in &slice.endpoints {
            if let Some(conditions) = &endpoint.conditions
                && endpoint_ready(conditions)
            {
                for ip in &endpoint.addresses {
                    let Ok(ip) = ip.parse() else {
                        continue;
                    };
                    ips.push(ip);
                }
            }
        }
        ips
    }

    fn backend_port_from_ep_slice(
        slice: &EndpointSlice,
        name: &str,
        protocol: KubeProtocol,
    ) -> Option<u16> {
        let Some(ports) = &slice.ports else {
            return None;
        };
        for p in ports {
            if p.name.as_deref() == Some(name)
                && let Some(port) = p.port
                && kube_proto_from_str(&p.protocol) == protocol
            {
                return Some(port as u16);
            }
        }
        None
    }

    fn service_names_ports_protocols(service: &Service) -> Vec<(String, u16, KubeProtocol)> {
        let mut names = Vec::new();
        if let Some(spec) = &service.spec
            && let Some(service_ports) = &spec.ports
        {
            for sp in service_ports {
                let protocol = if let Some(protocol) = &sp.protocol
                    && let Ok(protocol) = protocol.as_str().try_into()
                {
                    protocol
                } else {
                    continue;
                };
                if let Some(name) = &sp.name {
                    names.push((name.clone(), sp.port as u16, protocol));
                } else {
                    names.push((String::new(), sp.port as u16, protocol));
                }
            }
        }
        names
    }
}
