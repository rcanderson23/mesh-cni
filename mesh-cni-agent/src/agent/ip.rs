use std::net::IpAddr;
use std::sync::Arc;

use aya::maps::{HashMap, MapData};
use dashmap::DashMap;
use mesh_cni_api::ip::v1::{IpId, ListIpsReply, ListIpsRequest};
use mesh_cni_common::{Ip, IpStateId};
use tokio::sync::Mutex;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinHandle;
use tonic::{Request, Response, Status};
use tracing::{error, info};

use crate::Result;
use crate::kubernetes::{Labels, PodIdentityEvent};

use mesh_cni_api::ip::v1::ip_server::Ip as IpApi;

const STARTING_CLUSTER_POD_CAPACITY: usize = 1000;

pub struct IpState {
    pub labels_to_id: DashMap<Labels, IpStateId>,
    pub ip_to_labels_id: DashMap<IpAddr, (Labels, IpStateId)>,
    // TODO: this only works for ipv4
    ip_to_id: HashMap<MapData, Ip, IpStateId>,
    id: IpStateId,
    // rx: Receiver<PodIdentityEvent>,
}

impl IpState {
    fn new(ip_to_id: HashMap<MapData, Ip, IpStateId>) -> Self {
        Self {
            labels_to_id: DashMap::with_capacity(STARTING_CLUSTER_POD_CAPACITY),
            ip_to_labels_id: DashMap::with_capacity(STARTING_CLUSTER_POD_CAPACITY),
            // id less than 128 are reserved for cluster specific items
            id: 128,
            ip_to_id,
            // rx,
        }
    }
    // TODO: check if this can error with notifications
    pub async fn insert(&mut self, ip: IpAddr, labels: &Labels) -> Result<()> {
        if let Some(current) = self.ip_to_labels_id.get(&ip)
            && current.0 == *labels
        {
            return Ok(());
        }

        //TODO: if changes occur, you need to notify network policy
        let ebpf_addr = Ip::from(ip);
        self.ip_to_id.insert(ebpf_addr, self.id, 0)?;
        let _ = self.labels_to_id.insert(labels.clone(), self.id);
        let _ = self
            .ip_to_labels_id
            .insert(ip, (labels.to_owned(), self.id));

        self.id += 1;

        Ok(())
    }

    // TODO: check if this can error with notifications
    pub fn delete(&mut self, ip: IpAddr) -> Result<()> {
        let ebpf_addr = Ip::from(ip);
        self.ip_to_id.remove(&ebpf_addr)?;
        let labels_id = self.ip_to_labels_id.remove(&ip);
        if let Some(labels_id) = labels_id {
            self.labels_to_id.remove(&labels_id.1.0);
        };
        Ok(())
    }

    pub fn get_id_from_labels(&self, labels: &Labels) -> Option<IpStateId> {
        self.labels_to_id.get(labels).map(|id| *id)
    }
}

#[derive(Clone)]
pub struct IpServ {
    state: Arc<Mutex<IpState>>,
}

impl IpServ {
    pub async fn from(
        ip_to_id: HashMap<MapData, Ip, IpStateId>,
        rx: Receiver<PodIdentityEvent>,
    ) -> Self {
        let state = IpState::new(ip_to_id);
        let state = Arc::new(Mutex::new(state));
        // TODO:
        tokio::spawn(run(state.clone(), rx));

        Self { state }
    }
}

async fn run(state: Arc<Mutex<IpState>>, mut rx: Receiver<PodIdentityEvent>) -> Result<()> {
    while let Some(ev) = rx.recv().await {
        let mut state = state.lock().await;
        match ev {
            PodIdentityEvent::Add(pod_identity) => {
                for ip in pod_identity.ips {
                    info!("inserting pod identity {}", ip);
                    if let Err(e) = state.insert(ip, &pod_identity.labels).await {
                        error!("{e}: failed to insert pod identity {}", ip);
                    };
                }
            }
            PodIdentityEvent::Delete(ip) => {
                info!("deletig pod identity {}", ip);
                if let Err(e) = state.delete(ip) {
                    error!("{}: failed to delete pod identity {}", ip, e);
                };
            }
        }
        for key in state.ip_to_id.keys() {
            match key {
                Ok(key) => {
                    info!("ip to id map contains key {:?}", key);
                }
                Err(e) => {
                    error!("failed to get key {}", e);
                }
            }
        }
    }
    Ok(())
}

#[tonic::async_trait]
impl IpApi for IpServ {
    async fn list_ips(
        &self,
        _request: Request<ListIpsRequest>,
    ) -> Result<Response<ListIpsReply>, Status> {
        let state = self.state.lock().await;
        let ips = state
            .ip_to_labels_id
            .iter()
            .map(|k| IpId {
                ip: k.key().to_string(),
                id: k.1,
            })
            .collect();
        drop(state);
        let response = Response::new(ListIpsReply { ips });
        Ok(response)
    }
}
