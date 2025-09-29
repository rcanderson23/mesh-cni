use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::{EndpointConditions, EndpointSlice};
use kube::core::{Expression, Selector, SelectorExt};
use kube::runtime::reflector::{ObjectRef, ReflectHandle, Store};
use kube::{Api, ResourceExt};
use mesh_cni_ebpf_common::{KubeProtocol, service::ServiceKeyV4};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::pin::pin;
use std::sync::Arc;
use tokio::select;
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, info, warn};

use crate::kubernetes::{ClusterId, create_store_and_subscriber};
use crate::{Error, Result};

pub(crate) const SERVICE_OWNER_LABEL: &str = "kubernetes.io/service-name";

#[derive(Clone, Debug, PartialEq)]
pub enum EndpointEvent {
    Update(ServiceIdentity),
    Delete(ServiceKeyV4),
}

pub trait KubeStore<K: k8s_openapi::Metadata + kube::Resource> {
    fn get_store_state(&self) -> Vec<Arc<K>>;
    fn get_resource(&self, key: &ObjectRef<K>) -> Option<Arc<K>>;
}

impl<K> KubeStore<K> for Store<K>
where
    K: k8s_openapi::Metadata + kube::Resource + Clone,
    K::DynamicType: std::hash::Hash + std::cmp::Eq + Clone,
{
    fn get_store_state(&self) -> Vec<Arc<K>> {
        self.state()
    }

    fn get_resource(&self, key: &ObjectRef<K>) -> Option<Arc<K>> {
        self.get(key)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServiceIdentity {
    pub service_destination: ServiceKeyV4,
    pub ready_destinations: Vec<ServiceKeyV4>,
    pub cluster_id: ClusterId,
}

pub struct ServiceEndpointState {
    // TODO: make these an option to 'take'
    pub service_subscriber: ReflectHandle<Service>,
    pub endpoint_slice_subscriber: ReflectHandle<EndpointSlice>,
    pub cluster_id: ClusterId,
    tx: Sender<EndpointEvent>,
}

impl ServiceEndpointState {
    pub async fn try_new(
        client: kube::Client,
        cluster_id: ClusterId,
        tx: Sender<EndpointEvent>,
    ) -> Result<Self> {
        let service: Api<Service> = Api::all(client.clone());
        let endpoint_slice: Api<EndpointSlice> = Api::all(client);

        let (_service_store, service_subscriber) = create_store_and_subscriber(service).await?;
        let (_endpoint_slice_store, endpoint_slice_subscriber) =
            create_store_and_subscriber(endpoint_slice).await?;

        Ok(Self {
            service_subscriber,
            endpoint_slice_subscriber,
            cluster_id,
            tx,
        })
    }

    pub async fn start(&self) -> Result<()> {
        let service_store = self.service_subscriber.reader();
        let endpoint_slice_store = self.endpoint_slice_subscriber.reader();

        let service_handle = async {
            let svc_stream = self.service_subscriber.clone();
            let mut svc_stream = pin!(svc_stream);

            info!("started services watch");
            while let Some(svc) = svc_stream.next().await {
                match generate_endpoint_events(&endpoint_slice_store, svc.as_ref(), self.cluster_id)
                {
                    Ok(events) => {
                        for event in events {
                            if let Err(e) = self.tx.send(event).await {
                                error!(%e, "failed to send endpoint service event");
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            %e,
                            "failed to generate events from service {}/{}",
                            svc.namespace().unwrap_or_default(),
                            svc.name_any()
                        );
                        continue;
                    }
                };
            }
        };

        // regardless of the updated object, we should follow the same path regardless if it is a
        // service or slice update so that we ensure that we are sending the full ready endpoints
        let slice_handle = async {
            let slice_stream = self.endpoint_slice_subscriber.clone();
            let mut slice_stream = pin!(slice_stream);

            info!("started endpoint slice watch");
            while let Some(slice) = slice_stream.next().await {
                debug!(
                    "encountered endpoint slice update for {}/{}",
                    slice.namespace().unwrap_or_default(),
                    slice.name_any()
                );
                let Some(svc) = service_from_endpoint_slice(&service_store, &slice) else {
                    warn!(
                        "failed to get service from endpoint slice {}/{}",
                        slice.namespace().unwrap_or_default(),
                        slice.name_any()
                    );
                    continue;
                };

                match generate_endpoint_events(&endpoint_slice_store, svc.as_ref(), self.cluster_id)
                {
                    Ok(events) => {
                        for event in events {
                            if let Err(e) = self.tx.send(event).await {
                                error!(%e, "failed to send endpoint service event");
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            %e,
                            "failed to generate events from service {}/{}",
                            svc.namespace().unwrap_or_default(),
                            svc.name_any()
                        );
                        continue;
                    }
                };
            }
        };

        select! {
            _ = service_handle => {},
            _ = slice_handle => {},
        }

        Ok(())
    }
}

struct MinService {
    ips: Vec<IpAddr>,
    named_ports: Vec<NamedPort>,
}

struct NamedPort {
    name: String,
    port: u16,
    protocol: KubeProtocol,
}

impl TryFrom<&Service> for MinService {
    type Error = crate::Error;

    fn try_from(value: &Service) -> Result<Self, Self::Error> {
        let Some(spec) = &value.spec else {
            return Err(Error::ConversionError(
                "Service is missing spec field".into(),
            ));
        };
        // TODO: how to handle headless services?
        let Some(ips) = &spec.cluster_ips else {
            return Err(Error::ConversionError(
                "Service does not have any ClusterIPs".into(),
            ));
        };
        let ips = ips.iter().filter_map(|ip| ip.parse().ok()).collect();

        let named_ports = spec
            .ports
            .iter()
            .flat_map(|svc_ports| {
                svc_ports.iter().filter_map(|svc_port| {
                    let (Some(name), Ok(port), protocol) = (
                        &svc_port.name,
                        u16::try_from(svc_port.port),
                        kube_proto_from_str(&svc_port.protocol),
                    ) else {
                        return None;
                    };
                    Some(NamedPort {
                        name: name.to_owned(),
                        port,
                        protocol,
                    })
                })
            })
            .collect();

        Ok(MinService { ips, named_ports })
    }
}

fn service_from_endpoint_slice<T: KubeStore<Service>>(
    store: &T,
    slice: &EndpointSlice,
) -> Option<Arc<Service>> {
    let name = slice.labels().get(SERVICE_OWNER_LABEL)?;
    let namespace = slice.namespace()?;

    let obj_ref = ObjectRef::new(name).within(&namespace);
    store.get_resource(&obj_ref)
}

fn endpoint_slices_owned_by_service<T: KubeStore<EndpointSlice>>(
    store: &T,
    svc: &Service,
) -> Vec<Arc<EndpointSlice>> {
    let selector: Selector = Expression::Equal(SERVICE_OWNER_LABEL.into(), svc.name_any()).into();

    let state = store.get_store_state();
    state
        .iter()
        .filter(|s| selector.matches(s.labels()))
        .map(|s| s.to_owned())
        .collect()
}

fn endpoint_ready(ep_cond: &EndpointConditions) -> bool {
    (ep_cond.ready == Some(true) || ep_cond.ready.is_none()) && (ep_cond.terminating != Some(true))
}

fn generate_endpoint_events<T: KubeStore<EndpointSlice>>(
    store: &T,
    svc: &Service,
    cluster_id: ClusterId,
) -> Result<Vec<EndpointEvent>> {
    let min = MinService::try_from(svc)?;
    if svc.metadata.deletion_timestamp.is_some() {
        let mut events = vec![];
        for ip in min.ips {
            for np in &min.named_ports {
                match ip {
                    IpAddr::V4(ipv4_addr) => {
                        events.push(EndpointEvent::Delete(ServiceKeyV4 {
                            ip: ipv4_addr.into(),
                            port: np.port,
                            protocol: np.protocol as u8,
                        }));
                    }
                    // TODO: Add Ipv6
                    IpAddr::V6(_) => {}
                }
            }
        }
        return Ok(events);
    }

    let slices = endpoint_slices_owned_by_service(store, svc);

    let mut destinations_map: BTreeMap<String, Vec<ServiceKeyV4>> = BTreeMap::new();
    for slice in slices {
        let dsts = destinations_from_ep_slice(slice.as_ref());
        for (k, mut v) in dsts {
            match destinations_map.get_mut(&k) {
                Some(ep) => {
                    v.append(ep);
                    destinations_map.insert(k, v)
                }
                None => destinations_map.insert(k, v),
            };
        }
    }
    let mut events = vec![];
    for ip in min.ips {
        for np in &min.named_ports {
            match ip {
                IpAddr::V4(ipv4_addr) => {
                    let service_destination = ServiceKeyV4 {
                        ip: ipv4_addr.into(),
                        port: np.port,
                        protocol: np.protocol as u8,
                    };
                    let ready_destinations = destinations_map.remove(&np.name).unwrap_or_default();
                    events.push(EndpointEvent::Update(ServiceIdentity {
                        service_destination,
                        ready_destinations,
                        cluster_id,
                    }));
                }
                // TODO: Add Ipv6
                IpAddr::V6(_) => {}
            }
        }
    }

    Ok(events)
}

/// Returns ready destinations from an EndpointSlice
fn destinations_from_ep_slice(slice: &EndpointSlice) -> BTreeMap<String, Vec<ServiceKeyV4>> {
    let addrs: Vec<String> = slice
        .endpoints
        .iter()
        .filter_map(|ep| match &ep.conditions {
            Some(ec) => match endpoint_ready(ec) {
                true => Some(ep.addresses.to_owned()),
                false => None,
            },
            None => None,
        })
        .flatten()
        .collect();
    let port_proto_names: Vec<(i32, String, String)> = slice
        .ports
        .iter()
        .flat_map(|p| {
            p.iter()
                .filter_map(|p| match (&p.port, &p.protocol, p.name.to_owned()) {
                    (Some(p), Some(proto), Some(name)) => {
                        Some((*p, proto.to_owned(), name.to_owned()))
                    }
                    _ => None,
                })
        })
        .collect();

    let mut dwp = BTreeMap::new();
    for port_proto_name in &port_proto_names {
        let Ok(port) = u16::try_from(port_proto_name.0) else {
            warn!(
                "failed to parse port {} parsing EndpointSlice {}/{}",
                port_proto_name.0,
                slice.namespace().unwrap_or_default(),
                slice.name_any()
            );
            continue;
        };
        let protocol = KubeProtocol::try_from(port_proto_name.1.as_str()).unwrap_or_default() as u8;
        let destinations: Vec<ServiceKeyV4> = addrs.iter().filter_map(|addr| match addr.parse::<IpAddr>(){
            Ok(ip) => {
                match ip{
                    IpAddr::V4(ipv4_addr) => Some(ServiceKeyV4{ip: ipv4_addr.into(), port, protocol}),
                    // TODO: Add ipv6 support
                    IpAddr::V6(_) => None,
                }
            },
            Err(e) => {
                error!(%e, "failed to parse address {} from EndpointSlice {}/{}", addr, slice.namespace().unwrap_or_default() ,slice.name_any());
                None
            },
        }).collect();
        dwp.insert(port_proto_name.2.to_string(), destinations.to_owned());
    }
    dwp
}

fn kube_proto_from_str(proto: &Option<String>) -> KubeProtocol {
    match proto {
        Some(p) => KubeProtocol::try_from(p.as_str()).unwrap_or_default(),
        None => KubeProtocol::Tcp,
    }
}

#[cfg(test)]
mod test {

    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use k8s_openapi::api::core::v1::{ServicePort, ServiceSpec};
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointPort};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use k8s_openapi::chrono::Utc;
    use kube::api::ObjectMeta;
    use mesh_cni_ebpf_common::service::ServiceKeyV4;

    use super::*;

    struct TestStore<K>
    where
        K: k8s_openapi::Metadata + kube::Resource + Clone,
        K::DynamicType: std::hash::Hash + std::cmp::Eq + Clone,
    {
        map: HashMap<ObjectRef<K>, Arc<K>>,
    }

    impl<K> KubeStore<K> for TestStore<K>
    where
        K: k8s_openapi::Metadata + kube::Resource + Clone,
        K::DynamicType: std::hash::Hash + std::cmp::Eq + Clone,
    {
        fn get_store_state(&self) -> Vec<Arc<K>> {
            self.map.values().map(|k| k.to_owned()).collect()
        }

        fn get_resource(&self, key: &ObjectRef<K>) -> Option<Arc<K>> {
            self.map.get(key).map(|r| r.to_owned())
        }
    }

    #[test]
    fn test_generate_endpoint_events() {
        let mut slice_labels = BTreeMap::new();
        slice_labels.insert(SERVICE_OWNER_LABEL.to_string(), "test-name".to_string());
        let slice = EndpointSlice {
            address_type: "IPv4".into(),
            endpoints: vec![Endpoint {
                addresses: vec!["192.168.1.1".into()],
                conditions: Some(EndpointConditions {
                    ready: Some(true),
                    serving: Some(true),
                    terminating: None,
                }),
                ..Default::default()
            }],
            metadata: ObjectMeta {
                labels: Some(slice_labels),
                name: Some("test-name".into()),
                namespace: Some("test-namespace".into()),
                ..Default::default()
            },
            ports: Some(vec![EndpointPort {
                app_protocol: None,
                name: Some("http".into()),
                port: Some(80),
                protocol: Some("TCP".into()),
            }]),
        };

        let mut store = HashMap::new();
        store.insert(
            ObjectRef::new("test-name").within("test-namespace"),
            Arc::new(slice),
        );
        let store = TestStore { map: store };

        let mut svc = Service {
            metadata: ObjectMeta {
                name: Some("test-name".into()),
                namespace: Some("test-namespace".into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ips: Some(vec!["10.96.0.25".into()]),
                ports: Some(vec![ServicePort {
                    name: Some("http".into()),
                    port: 8080,
                    protocol: Some("TCP".into()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(
            generate_endpoint_events(&store, &svc, 1).unwrap(),
            vec![EndpointEvent::Update(ServiceIdentity {
                service_destination: ServiceKeyV4 {
                    ip: Ipv4Addr::new(10, 96, 0, 25).into(),
                    port: 8080,
                    protocol: KubeProtocol::Tcp as u8,
                },
                ready_destinations: vec![ServiceKeyV4 {
                    ip: Ipv4Addr::new(192, 168, 1, 1).into(),
                    port: 80,
                    protocol: KubeProtocol::Tcp as u8,
                }],
                cluster_id: 1,
            })]
        );

        svc.metadata.deletion_timestamp = Some(Time(Utc::now()));
        assert_eq!(
            generate_endpoint_events(&store, &svc, 1).unwrap(),
            vec![EndpointEvent::Delete(ServiceKeyV4 {
                ip: Ipv4Addr::new(10, 96, 0, 25).into(),
                port: 8080,
                protocol: KubeProtocol::Tcp as u8,
            })]
        );
    }

    #[test]
    fn test_destinations_from_ep_slice() {
        let slice = EndpointSlice {
            address_type: "IPv4".into(),
            endpoints: vec![Endpoint {
                addresses: vec!["192.168.1.1".into()],
                conditions: Some(EndpointConditions {
                    ready: Some(true),
                    serving: Some(true),
                    terminating: None,
                }),
                ..Default::default()
            }],
            metadata: ObjectMeta::default(),
            ports: Some(vec![EndpointPort {
                app_protocol: None,
                name: Some("http".into()),
                port: Some(80),
                protocol: Some("TCP".into()),
            }]),
        };
        let mut map = BTreeMap::new();
        map.insert(
            "http".into(),
            vec![ServiceKeyV4 {
                ip: Ipv4Addr::new(192, 168, 1, 1).into(),
                port: 80,
                protocol: KubeProtocol::Tcp as u8,
            }],
        );
        assert_eq!(destinations_from_ep_slice(&slice), map);
    }
}
