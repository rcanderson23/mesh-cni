use std::net::IpAddr;
use std::sync::Arc;

use aya::maps::{HashMap, MapData};
use dashmap::DashMap;
use homelab_cni_common::{Ip, IpStateId};
use tokio::sync::Mutex;
use tokio::sync::mpsc::Receiver;
use tracing::{error, info};

use crate::Result;
use crate::kubernetes::{Labels, PodIdentityEvent};

const STARTING_CLUSTER_POD_CAPACITY: usize = 1000;

pub struct IpState<'a> {
    pub labels_to_id: DashMap<Labels, IpStateId>,
    pub ip_to_labels_id: DashMap<IpAddr, (Labels, IpStateId)>,
    // TODO: this only works for ipv4
    ip_to_id: HashMap<&'a mut MapData, Ip, IpStateId>,
    id: Arc<Mutex<IpStateId>>,
    rx: Receiver<PodIdentityEvent>,
}

impl<'a> IpState<'a> {
    pub fn new(
        rx: Receiver<PodIdentityEvent>,
        ip_to_id: HashMap<&'a mut MapData, Ip, IpStateId>,
    ) -> Self {
        Self {
            labels_to_id: DashMap::with_capacity(STARTING_CLUSTER_POD_CAPACITY),
            ip_to_labels_id: DashMap::with_capacity(STARTING_CLUSTER_POD_CAPACITY),
            // id less than 128 are reserved for cluster specific items
            id: Arc::new(Mutex::new(128)),
            ip_to_id,
            rx,
        }
    }
    // TODO: check if this can error with notifications
    pub async fn insert(&mut self, ip: IpAddr, labels: &Labels) -> Result<()> {
        if let Some(current) = self.ip_to_labels_id.get(&ip)
            && current.0 == *labels
        {
            return Ok(());
        }
        let mut state_id = self.id.lock().await;

        //TODO: if changes occur, you need to notify network policy
        let ebpf_addr = Ip::from(ip);
        self.ip_to_id.insert(ebpf_addr, *state_id, 0)?;
        let _ = self.labels_to_id.insert(labels.clone(), *state_id);
        let _ = self
            .ip_to_labels_id
            .insert(ip, (labels.to_owned(), *state_id));

        *state_id += 1;

        Ok(())
    }

    // TODO: check if this can error with notifications
    pub fn delete(&mut self, ip: IpAddr) -> Result<()> {
        let ebpf_addr = Ip::from(ip);
        self.ip_to_id.remove(&ebpf_addr)?;
        let labels_id = self.ip_to_labels_id.remove(&ip);
        if let Some(labels_id) = labels_id {
            self.labels_to_id.remove(&labels_id.1.0);
        }
        Ok(())
    }

    pub fn get_id_from_labels(&self, labels: &Labels) -> Option<IpStateId> {
        self.labels_to_id.get(labels).map(|id| *id)
    }

    // TODO: fix this to properly handle errors
    pub async fn start(&mut self) -> Result<()> {
        while let Some(ev) = self.rx.recv().await {
            match ev {
                PodIdentityEvent::Add(pod_identity) => {
                    for ip in pod_identity.ips {
                        info!("inserting pod identity {}", ip);
                        if let Err(e) = self.insert(ip, &pod_identity.labels).await {
                            error!("{e}: failed to insert pod identity {}", ip);
                        };
                    }
                }
                PodIdentityEvent::Delete(ip) => {
                    info!("deletig pod identity {}", ip);
                    if let Err(e) = self.delete(ip) {
                        error!("{e}: failed to delete pod identity {}", ip);
                    };
                }
            }
        }
        Ok(())
    }
}

//

// fn pod_matches_node_name(pod: &Pod, node_name: &str) -> bool {
//     let Some(spec) = pod.spec.as_ref() else {
//         return false;
//     };
//     let Some(name) = spec.node_name.as_ref() else {
//         return false;
//     };
//     name == node_name
// }
