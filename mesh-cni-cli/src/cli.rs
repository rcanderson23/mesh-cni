use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(version, about = "A cli for interacting with mesh-cni-agent", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Clone, Subcommand, Debug)]
pub enum Commands {
    /// Used to interact with the IP subsystem
    #[command(subcommand)]
    Ip(IpCommands),
}

#[derive(Clone, Subcommand, Debug)]
pub enum IpCommands {
    /// List the IPs and their associated IDs
    List,
}
