use aya::maps::lpm_trie::Key as LpmKey;
use mesh_cni_api::ip::v1::{ListIpsReply, ListIpsRequest, ip_server::Ip as IpApi};
use mesh_cni_ebpf_common::Id;
use tonic::{Request, Response, Status};

use crate::{
    Result,
    bpf::{BpfMap, ip::state::IpNetworkState},
};

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
    pub fn new(state: IpNetworkState<IP4, IP6>) -> Self {
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
