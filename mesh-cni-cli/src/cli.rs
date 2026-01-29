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

    /// Used to interact with the Service subsystem
    #[command(subcommand)]
    Service(ServiceCommands),

    /// Used to interact with the Conntrack subsystem
    #[command(subcommand)]
    Conntrack(ConntrackCommands),

    /// Used to interact with the Conntrack subsystem
    #[command(subcommand)]
    Policy(PolicyCommands),
}

#[derive(Clone, Subcommand, Debug)]
pub enum IpCommands {
    /// List the IPs and their associated IDs
    List,
}

#[derive(Clone, Subcommand, Debug)]
pub enum ServiceCommands {
    /// List the Service and their associated IDs
    List {
        #[arg(long)]
        /// When set, pulls data from the bpf map instead of the cache
        from_map: bool,
    },
}

#[derive(Clone, Subcommand, Debug)]
pub enum ConntrackCommands {
    /// List the connections in the Conntrack
    List,
}

#[derive(Clone, Subcommand, Debug)]
pub enum PolicyCommands {
    /// List the policies currently enforced
    List,
}
