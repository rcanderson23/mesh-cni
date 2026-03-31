use std::{net::SocketAddr, path::PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use http::Uri;
use ipnetwork::IpNetwork;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Subcommand, Debug)]
pub enum Commands {
    Agent(AgentArgs),
    Controller(ControllerArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct AgentArgs {
    /// Cluster URL for agent to connect to the Kubernetes
    /// control plane without kube-proxy
    #[arg(long)]
    pub cluster_url: Uri,

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

    /// Netns directory
    #[arg(
        long,
        env = "AGENT_SOCKET_PATH",
        default_value = "/var/run/mesh/mesh.sock"
    )]
    pub agent_socket_path: PathBuf,

    /// Agent socket path
    #[arg(long, env = "NETNS_DIR", default_value = "/var/run/mesh/netns")]
    pub netns_dir: PathBuf,

    #[clap(flatten)]
    pub proxy_settings: ProxySettings,

    #[clap(flatten)]
    pub cni_settings: CniSettings,

    #[clap(flatten)]
    pub vxlan_settings: VxlanSettings,
}

#[derive(Parser, Debug, Clone)]
pub struct ProxySettings {
    #[clap(flatten)]
    pub node_port_settings: NodePortSettings,
}

#[derive(Parser, Debug, Clone)]
pub struct NodePortSettings {
    /// Determines the start port range for NodePort services
    #[arg(long, env = "NODE_PORT_START", default_value = "30000")]
    pub node_port_start: u16,

    /// Determines the end port range for NodePort services
    #[arg(long, env = "NODE_PORT_END", default_value = "32767")]
    pub node_port_end: u16,

    /// Regex used to select host interfaces for NodePort service tc attachments
    #[arg(long, env = "NODE_PORT_IFACE_REGEX", default_value = "^eth.*$")]
    pub node_port_iface_regex: String,
}

#[derive(Parser, Debug, Clone)]
pub struct CniSettings {
    /// CNI Bin directory
    #[arg(
        long = "cni-bin-dir",
        env = "CNI_BIN_DIR",
        default_value = "/opt/cni/bin"
    )]
    pub bin_dir: PathBuf,

    /// CNI configuration directory
    #[arg(
        long = "cni-conf-dir",
        env = "CNI_CONF_DIR",
        default_value = "/etc/cni/net.d"
    )]
    pub conf_dir: PathBuf,

    /// CNI plugin log path
    #[arg(
        long = "cni-plugin-log-dir",
        env = "CNI_PLUGIN_LOG_PATH",
        default_value = "/var/log/mesh-cni"
    )]
    pub plugin_log_dir: PathBuf,

    /// CNI plugin bin path
    #[arg(
        long = "cni-plugin-bin",
        env = "CNI_PLUGIN_BIN",
        default_value = "/app/mesh-cni-plugin"
    )]
    pub plugin_bin: PathBuf,

    /// Determines what mode the CNI should use
    #[arg(
        long,
        env = "MESH_CNI_MODE",
        value_enum,
        default_value_t = CniMode::Chained
    )]
    pub mode: CniMode,
}

#[derive(Parser, Debug, Clone)]
pub struct ControllerArgs {
    /// Metrics listener for agent
    #[arg(long, default_value = "0.0.0.0:9090")]
    pub metrics_address: SocketAddr,

    /// Namespace the controller is running in
    #[arg(long, env = "NAMESPACE")]
    pub namespace: String,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, PartialOrd)]
pub enum CniMode {
    Chained,
    Vxlan,
}

#[derive(Parser, Debug, Clone)]
pub struct VxlanSettings {
    /// Regex used to select host interfaces for vxlan dev
    #[arg(long, env = "MESH_CNI_VXLAN_IFACE_REGEX", default_value = "^eth.*$")]
    pub iface_regex: String,

    /// Comma separated Pod CIDRs. Accepts IPv4 and IPv6
    #[arg(
        long,
        env = "MESH_CNI_VXLAN_POD_CIDR",
        default_value = "10.244.0.0/16",
        value_delimiter = ','
    )]
    pub pod_cidrs: Vec<IpNetwork>,

    /// Interface to configure SNAT for pod traffic. Pattern will use first match.
    #[arg(long, env = "MESH_CNI_VXLAN_IFACE_SNAT", default_value = "^eth.*$")]
    pub iface_snat: String,
}
