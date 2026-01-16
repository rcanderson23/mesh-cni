use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    path::PathBuf,
};

use clap::Parser;
use ipnetwork::IpNetwork;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, Result};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Possible values are ADD, DEL, CHECK, GC, VERSION
    #[arg(long, env = "CNI_COMMAND", value_parser = parse_command)]
    pub command: Command,

    /// Container ID
    #[arg(long, env = "CNI_CONTAINERID")]
    pub container_id: String,

    /// Path to the network namespace
    #[arg(long, env = "CNI_NETNS")]
    pub net_ns: Option<PathBuf>,

    /// Extra arguments
    #[arg(long, env = "CNI_IFNAME")]
    pub ifname: String,

    /// Key-value pair seperated by semi-colons
    #[arg(long, env = "CNI_ARGS", value_parser = parse_key_value)]
    pub args: BTreeMap<String, String>,

    /// List of paths to search
    //#[arg(long, env = "CNI_PATH", value_parser = parse_path)]
    #[arg(long, env = "CNI_PATH")]
    pub paths: String,
}

fn parse_key_value(s: &str) -> Result<BTreeMap<String, String>> {
    let mut kv = BTreeMap::new();

    if s.is_empty() {
        return Ok(kv);
    };

    for split in s.split(";") {
        if let Some((k, v)) = split.split_once("=") {
            kv.insert(k.to_owned(), v.to_owned());
        }
    }

    Ok(kv)
}

fn _parse_path(s: &str) -> Result<Vec<String>> {
    if s.is_empty() {
        return Ok(vec![]);
    }
    Ok(s.split(":").map(|s| s.to_owned()).collect())
}

fn parse_command(s: &str) -> Result<Command> {
    let cmd = match s {
        "ADD" => Command::Add,
        "DEL" => Command::Delete,
        "CHECK" => Command::Check,
        "STATUS" => Command::Status,
        "VERSION" => Command::Version,
        "GC" => Command::Gc,
        _ => return Err(Error::Parse("command {s} not supported".into())),
    };
    Ok(cmd)
}

#[derive(Clone)]
pub enum Command {
    Add,
    Delete,
    Check,
    Status,
    Version,
    Gc,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(
        serialize_with = "crate::serialize_to_string",
        deserialize_with = "crate::deserialize_from_str"
    )]
    /// cni version
    pub cni_version: Version,
    #[serde(
        serialize_with = "crate::serialize_to_string_slice",
        deserialize_with = "crate::deserialize_from_str_vec",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    /// supported cni versions
    pub cni_versions: Vec<Version>,

    /// Name of the config
    pub name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Disable the Check command
    pub disable_check: Option<bool>,

    #[serde(default, rename = "disableGC", skip_serializing_if = "Option::is_none")]
    /// Disable the GC command
    pub disable_gc: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_only_inlined_plugins: Option<bool>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// List of chained plugins
    pub plugins: Vec<PluginConfig>,
}

/// https://www.cni.dev/docs/spec/#plugin-configuration-objects
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginConfig {
    /// Matches the name of the CNI plugin binary on disk.
    /// Must not contain characters disallowed in file paths for the system (e.g. / or \).
    pub r#type: String,

    #[serde(flatten)]
    pub options: HashMap<String, Value>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    /// A list of portmapping entries.
    pub port_mappings: Vec<PortMapping>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    //TODO: replace with proto enum?
    pub protocol: String,
}

#[derive(Serialize, Deserialize)]
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
