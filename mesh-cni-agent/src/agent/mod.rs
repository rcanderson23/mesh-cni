pub mod bpf;
pub mod ip;
pub mod metrics;
pub mod service;

use std::borrow::BorrowMut;
use std::fs;
use std::hash::Hash;
use std::io::ErrorKind;
use std::path::PathBuf;

use ahash::HashMapExt;
use aya::Pod;
use aya::maps::{HashMap, MapData};
use mesh_cni_api::bpf::v1::bpf_server::BpfServer;
use mesh_cni_common::Id;
use mesh_cni_common::service_v4::{EndpointKeyV4, EndpointValueV4, ServiceKeyV4, ServiceValueV4};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::service::{Routes, RoutesBuilder};
use tonic::transport::Server;
use tracing::{error, info};

use crate::config::ControllerArgs;
use crate::http::shutdown;
use crate::{Error, Result};

pub trait BpfMap<K, V> {
    fn update(&mut self, key: K, value: V) -> Result<()>;
    fn delete(&mut self, key: &K) -> Result<()>;
    fn get(&self, key: &K) -> Result<V>;
    fn get_state(&self) -> Result<ahash::HashMap<K, V>>;
}

impl<T: BorrowMut<MapData>, K: Pod + Eq + Hash, V: Pod> BpfMap<K, V> for HashMap<T, K, V> {
    fn update(&mut self, key: K, value: V) -> Result<()> {
        Ok(self.insert(key, value, 0)?)
    }
    fn delete(&mut self, key: &K) -> Result<()> {
        Ok(self.remove(key)?)
    }
    fn get(&self, key: &K) -> Result<V> {
        Ok(<HashMap<T, K, V>>::get(self, key, 0)?)
    }
    fn get_state(&self) -> Result<ahash::HashMap<K, V>> {
        let mut map = ahash::HashMap::new();
        for v in self.iter() {
            match v {
                Ok((k, v)) => {
                    map.insert(k, v);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(map)
    }
}

pub struct BpfState<M, K, V>
where
    M: BpfMap<K, V>,
    K: std::hash::Hash + std::cmp::Eq + Clone,
    V: Clone + std::cmp::PartialEq,
{
    cache: ahash::HashMap<K, V>,
    bpf_map: M,
}

impl<M, K, V> BpfState<M, K, V>
where
    M: BpfMap<K, V>,
    K: std::hash::Hash + std::cmp::Eq + Clone,
    V: Clone + std::cmp::PartialEq,
{
    pub fn new(bpf_map: M) -> Self {
        let cache = ahash::HashMap::default();
        Self { cache, bpf_map }
    }

    pub fn update(&mut self, key: K, value: V) -> Result<()> {
        if let Some(current) = self.cache.get(&key)
            && *current == value
        {
            return Ok(());
        };
        match self.bpf_map.update(key.clone(), value.clone()) {
            Ok(_) => {
                self.cache.insert(key, value);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn delete(&mut self, key: &K) -> Result<()> {
        match self.bpf_map.delete(key) {
            Ok(_) => {
                self.cache.remove(key);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn get_from_cache(&self, key: &K) -> Option<&V> {
        if let Some(val) = self.cache.get(key) {
            Some(val)
        } else {
            None
        }
    }
    pub fn get_from_map(&self, key: &K) -> Result<V> {
        self.bpf_map.get(key)
    }
}

pub async fn start(args: ControllerArgs, cancel: CancellationToken) -> Result<()> {
    // TODO: configure this dynamically for all clusters configured in mesh
    let kube_client = kube::Client::try_default().await?;
    let bpf = bpf::State::try_new()?;

    // TODO: bpf maps should be pinned and loaded from pinned location
    let ipv4_map: HashMap<MapData, u32, Id> = bpf
        .take_map("IPV4_IDENTITY")
        .await
        .ok_or_else(|| Error::MapNotFound {
            name: "IPV4_IDENTITY".into(),
        })?
        .try_into()?;
    let ipv6_map: HashMap<MapData, u128, Id> = bpf
        .take_map("IPV6_IDENTITY")
        .await
        .ok_or_else(|| Error::MapNotFound {
            name: "IPV6_IDENTITY".into(),
        })?
        .try_into()?;

    let service_map: HashMap<MapData, ServiceKeyV4, ServiceValueV4> = bpf
        .take_map("SERVICES")
        .await
        .ok_or_else(|| Error::MapNotFound {
            name: "SERVICES".into(),
        })?
        .try_into()?;

    let endpoint_map: HashMap<MapData, EndpointKeyV4, EndpointValueV4> = bpf
        .take_map("ENDPOINTS")
        .await
        .ok_or_else(|| Error::MapNotFound {
            name: "ENDPOINTS".into(),
        })?
        .try_into()?;

    let (ip_server, ip_handle) =
        ip::run(ipv4_map, ipv6_map, kube_client.clone(), args.cluster_id).await?;

    let (service_server, service_handle) = service::run(
        service_map,
        endpoint_map,
        kube_client.clone(),
        args.cluster_id,
    )
    .await?;

    let bpf_server = BpfServer::new(bpf);

    let mut routes = RoutesBuilder::default();
    let routes = routes
        .add_service(bpf_server)
        .add_service(ip_server)
        .add_service(service_server);
    let routes = routes.to_owned().routes();
    let server_handle = serve(args.agent_socket_path, routes, cancel.child_token());

    // TODO: add graceful shutdown
    tokio::select! {
        _ = cancel.cancelled() => {},
        h = server_handle => exit("bpf", h),
        h = service_handle => exit("service", h.map_err(|e| Error::Task(e.to_string()))?),
        h = ip_handle => exit("ip", h.map_err(|e| Error::Task(e.to_string()))?),
    }
    Ok(())
}

fn exit(task: &str, out: Result<()>) {
    match out {
        Ok(_) => {
            info!("{task} exited")
        }
        Err(e) => {
            error!("{task} failed with error: {e}")
        }
    }
}

pub(crate) async fn serve(path: PathBuf, routes: Routes, cancel: CancellationToken) -> Result<()> {
    if let Err(e) = fs::remove_file(&path)
        && e.kind() != ErrorKind::NotFound
    {
        return Err(e.into());
    }
    let Some(parent) = path.parent() else {
        return Err(std::io::Error::new(
            ErrorKind::NotFound,
            format!("parent of path {} could not resolve", path.display()),
        )
        .into());
    };
    fs::create_dir_all(parent)?;
    let listener = UnixListener::bind(&path)?;

    let stream = UnixListenerStream::new(listener);

    Server::builder()
        .add_routes(routes)
        .serve_with_incoming_shutdown(stream, shutdown(cancel))
        .await?;

    Ok(())
}
