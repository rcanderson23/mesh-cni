use std::net::SocketAddr;

use clap::{Parser, Subcommand};

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
    /// Metrics listener for agent
    #[arg(long, default_value = "0.0.0.0:9090")]
    pub metrics_address: SocketAddr,

    /// Metrics listener for agent
    #[arg(long, default_value = "0.0.0.0:9090")]
    pub opentelemetry_address: Option<String>,

    /// Interface to bind bpf program to
    #[arg(long, default_value = "eth0")]
    pub iface: String,
}
