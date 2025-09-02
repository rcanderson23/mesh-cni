use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::kubernetes::ClusterId;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Clone, Subcommand, Debug)]
pub enum Commands {
    Controller(ControllerArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct ControllerArgs {
    /// Path to the bpf fs for bpf maps
    #[arg(long, default_value = "/sys/fs/bpf")]
    pub bpf_fs: PathBuf,

    /// Path to the cgroup fs
    #[arg(long, default_value = "/sys/fs/cgroup")]
    pub cgroup_fs: PathBuf,

    /// Metrics listener for agent
    #[arg(long, default_value = "0.0.0.0:9090")]
    pub metrics_address: SocketAddr,

    /// OpenTelemetry endpoint
    #[arg(long, default_value = "127.0.0.1:4317")]
    pub opentelemetry_address: Option<String>,

    /// Interface to bind bpf program to
    #[arg(long, default_value = "eth0")]
    pub iface: String,

    /// Name of the node the program is running on
    #[arg(long, env = "NODE_NAME")]
    pub node_name: String,

    /// Unique ID for the cluster among the clustermesh
    #[arg(long, env = "CLUSTER_ID")]
    pub cluster_id: ClusterId,

    /// CNI Bin directory
    #[arg(long, env = "CNI_BIN_DIR", default_value = "/opt/cni/bin")]
    pub cni_bin_dir: PathBuf,

    /// CNI configuration directory
    #[arg(long, env = "CNI_CONF_DIR", default_value = "/etc/cni/net.d")]
    pub cni_conf_dir: PathBuf,

    /// CNI plugin log path
    #[arg(long, env = "CNI_PLUGIN_LOG_PATH", default_value = "/var/log/mesh-cni")]
    pub cni_plugin_log_dir: PathBuf,

    /// Cluster configs path
    #[arg(
        long,
        env = "MESH_CLUSTERS_CONFIG",
        default_value = "/etc/mesh-cni/cluster-config"
    )]
    pub mesh_clusters_config: PathBuf,

    /// Agent socket path
    #[arg(
        long,
        env = "AGENT_SOCKET_PATH",
        default_value = "/var/run/mesh/mesh.sock"
    )]
    pub agent_socket_path: PathBuf,
}
