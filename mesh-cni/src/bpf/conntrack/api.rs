use std::net::Ipv4Addr;

use anyhow::bail;
use mesh_cni_api::conntrack::v1::{
    Connection, GetConntrackReply, GetConntrackRequest, conntrack_server::Conntrack as ConntrackApi,
};
use mesh_cni_ebpf_common::conntrack::ConntrackKeyV4;
use tonic::{Code, Request, Response, Status};
use tracing::{error, info};

use crate::{Result, bpf::conntrack::load_map};

pub struct Conntrack;

#[tonic::async_trait]
impl ConntrackApi for Conntrack {
    async fn get_conntrack(
        &self,
        _request: Request<GetConntrackRequest>,
    ) -> std::result::Result<Response<GetConntrackReply>, Status> {
        info!("conntrack request");
        let map = load_map().map_err(|e: anyhow::Error| {
            tonic::Status::new(Code::Internal, format!("failed to load map: {}", e))
        })?;

        let connections = map
            .keys()
            .filter_map(|key| {
                let key = match key {
                    Ok(key) => key,
                    Err(_) => {
                        return None;
                    }
                };
                match connection_from_keyv4(&key) {
                    Ok(cxn) => Some(cxn),
                    Err(e) => {
                        error!(%e, "failed to convert key to connection");
                        None
                    }
                }
            })
            .collect();

        Ok(Response::new(GetConntrackReply { connections }))
    }
}

fn connection_from_keyv4(key: &ConntrackKeyV4) -> Result<Connection> {
    let src_ip = Ipv4Addr::from_bits(key.src_ip).to_string();
    let dst_ip = Ipv4Addr::from_bits(key.dst_ip).to_string();
    let proto = match key.proto {
        1 => "ICMPv4",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        132 => "SCTP",
        _ => bail!("unsupported proto found in conntrack key"),
    };

    Ok(Connection {
        src_ip,
        src_port: key.src_port as u32,
        dst_ip,
        dst_port: key.dst_port as u32,
        proto: proto.to_string(),
    })
}
