use aya::maps::lpm_trie::Key as LpmKey;
use mesh_cni_api::ip::v1::ip_server::Ip as IpApi;
use mesh_cni_api::ip::v1::{ListIpsReply, ListIpsRequest};
use mesh_cni_common::Id;
use tokio::sync::mpsc::Receiver;
use tonic::{Request, Response, Status};
use tracing::{error, info};

use crate::Result;
use crate::bpf::BpfMap;
use crate::bpf::ip::state::IpNetworkState;
use crate::kubernetes::pod::PodIdentityEvent;

#[derive(Clone)]
pub struct Server<IP4, IP6>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = Id>,
    IP6: BpfMap<Key = LpmKey<u128>, Value = Id>,
{
    state: IpNetworkState<IP4, IP6>,
}

impl<IP4, IP6> Server<IP4, IP6>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = Id> + Send + 'static,
    IP6: BpfMap<Key = LpmKey<u128>, Value = Id> + Send + 'static,
{
    pub async fn from(state: IpNetworkState<IP4, IP6>, rx: Receiver<PodIdentityEvent>) -> Self {
        tokio::spawn(start_event_receiver(state.clone(), rx));

        Self { state }
    }
}

#[tonic::async_trait]
impl<IP4, IP6> IpApi for Server<IP4, IP6>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = Id> + Send + 'static,
    IP6: BpfMap<Key = LpmKey<u128>, Value = Id> + Send + 'static,
{
    async fn list_ips(
        &self,
        _request: Request<ListIpsRequest>,
    ) -> Result<Response<ListIpsReply>, Status> {
        let ips = self.state.get_ip_labels_id();
        let response = Response::new(ListIpsReply { ips });
        Ok(response)
    }
}

async fn start_event_receiver<IP4, IP6>(
    state: IpNetworkState<IP4, IP6>,
    mut rx: Receiver<PodIdentityEvent>,
) -> Result<()>
where
    IP4: BpfMap<Key = LpmKey<u32>, Value = Id> + Send,
    IP6: BpfMap<Key = LpmKey<u128>, Value = Id> + Send,
{
    while let Some(ev) = rx.recv().await {
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
