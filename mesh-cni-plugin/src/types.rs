use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use ipnetwork::IpNetwork;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    #[serde(
        serialize_with = "crate::serialize_to_string",
        deserialize_with = "crate::deserialize_from_str"
    )]
    pub cni_version: Version,

    #[serde(default)]
    pub name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_config: Option<RuntimeConfig>,

    #[serde(
        default,
        rename = "prevResult",
        skip_serializing_if = "Option::is_none"
    )]
    pub previous_result: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Interface {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<PathBuf>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<String>,

    #[serde(default, rename = "pciID", skip_serializing_if = "Option::is_none")]
    pub pci_id: Option<String>,
}

// impl From<mesh_cni_api::bpf::v1::Interface> for Interface {
//     fn from(value: mesh_cni_api::bpf::v1::Interface) -> Self {
//         let sandbox = if let Some(sandbox) = value.sandbox {
//             Some(PathBuf::from_str(&sandbox).unwrap_or_default())
//         } else {
//             None
//         };
//         Self {
//             name: value.name,
//             mac: value.mac,
//             mtu: value.mtu,
//             sandbox,
//             socket_path: value.socket_path,
//             pci_id: value.pci_id,
//         }
//     }
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ip {
    #[serde(
        serialize_with = "crate::serialize_to_string",
        deserialize_with = "crate::deserialize_from_str"
    )]
    pub address: IpNetwork,
    pub gateway: IpAddr,
    pub interface: Option<usize>,
}

// impl TryFrom<mesh_cni_api::bpf::v1::Ip> for Ip {
//     fn try_from(value: mesh_cni_api::bpf::v1::Ip) -> Result<Self, Error> {
//         type Error = crate::Error
//         let Some(address) = value.address.split_once("/").ok_or_else(||crate::Error::Parse("failed to split address at cidr"))
//         Self {
//             address: value.address,
//             gateway: value.gateway,
//             interface: value.iface,
//         }
//     }
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dns {
    #[serde(
        serialize_with = "crate::serialize_to_string_slice",
        deserialize_with = "crate::deserialize_from_str_vec",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub nameservers: Vec<IpAddr>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    #[serde(
        serialize_with = "crate::serialize_to_string",
        deserialize_with = "crate::deserialize_from_str"
    )]
    pub dst: IpNetwork,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gw: Option<IpAddr>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advmss: Option<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<u8>,
}

/// https://www.cni.dev/docs/conventions/#well-known-capabilities
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeConfig {
    /// A list of portmapping entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_mappings: Option<Vec<PortMapping>>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_ranges: Vec<IpRange>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<Bandwidth>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Dns>,

    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "crate::serialize_to_string_slice",
        deserialize_with = "crate::deserialize_from_str_vec"
    )]
    pub ips: Vec<IpNetwork>,

    // TODO: use macaddr type?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,

    #[serde(
        default,
        rename = "infinibandGUID",
        skip_serializing_if = "Option::is_none"
    )]
    pub infiniband_guid: Option<String>,

    #[serde(default, rename = "deviceID", skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,

    /// Contains plugin plugin specific values that are not
    /// "well-known" types.
    #[serde(flatten)]
    pub other: HashMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    //TODO: replace with proto enum?
    pub protocol: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpRange {
    #[serde(
        serialize_with = "crate::serialize_to_string",
        deserialize_with = "crate::deserialize_from_str"
    )]
    pub subnet: IpNetwork,
    pub range_start: IpAddr,
    pub range_end: IpAddr,
    pub gateway: IpAddr,
}

/// Desired bandwidth limits. Rates are in bits per second,
/// burst values are in bits
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bandwidth {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_rate: Option<usize>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_burst: Option<usize>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_rate: Option<usize>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_burst: Option<usize>,
}
