use std::sync::Arc;

use mesh_cni_api::ip::v1::ip_server::Ip as IpApi;
use mesh_cni_api::ip::v1::{IpId, ListIpsReply, ListIpsRequest};
use mesh_cni_common::Id;
use tokio::sync::Mutex;
use tokio::sync::mpsc::Receiver;
use tonic::{Request, Response, Status};
use tracing::{error, info};

use crate::Result;
use crate::agent::BpfMap;
use crate::agent::ip::state::State;
use crate::kubernetes::pod::PodIdentityEvent;

#[derive(Clone)]
pub struct Server<I, P>
where
    I: BpfMap<u32, Id>,
    P: BpfMap<u128, Id>,
{
    state: Arc<Mutex<State<I, P>>>,
}

impl<I, P> Server<I, P>
where
    I: BpfMap<u32, Id> + Send + 'static,
    P: BpfMap<u128, Id> + Send + 'static,
{
    pub async fn from(state: State<I, P>, rx: Receiver<PodIdentityEvent>) -> Self {
        let state = Arc::new(Mutex::new(state));
        // TODO:
        tokio::spawn(start_event_receiver(state.clone(), rx));

        Self { state }
    }
}

#[tonic::async_trait]
impl<I, P> IpApi for Server<I, P>
where
    I: BpfMap<u32, Id> + Send + 'static,
    P: BpfMap<u128, Id> + Send + 'static,
{
    async fn list_ips(
        &self,
        _request: Request<ListIpsRequest>,
    ) -> Result<Response<ListIpsReply>, Status> {
        let state = self.state.lock().await;
        let ips = state
            .ip_to_labels_id
            .iter()
            .map(|(ip, (labels, id))| IpId {
                ip: ip.to_string(),
                labels: labels.to_hashmap(),
                id: *id as u32,
            })
            .collect();
        drop(state);
        let response = Response::new(ListIpsReply { ips });
        Ok(response)
    }
}

async fn start_event_receiver<I, P>(
    state: Arc<Mutex<State<I, P>>>,
    mut rx: Receiver<PodIdentityEvent>,
) -> Result<()>
where
    I: BpfMap<u32, Id> + Send,
    P: BpfMap<u128, Id> + Send,
{
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
    }
    Ok(())
}
