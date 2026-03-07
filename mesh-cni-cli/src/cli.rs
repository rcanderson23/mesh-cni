use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(version, about = "A cli for interacting with mesh-cni-agent", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Clone, Debug, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
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
    List {
        #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
}

#[derive(Clone, Subcommand, Debug)]
pub enum ServiceCommands {
    /// List the Service and their associated IDs
    List {
        #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// List NodePort to Service mappings
    ListNodePorts {
        #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
}

#[derive(Clone, Subcommand, Debug)]
pub enum ConntrackCommands {
    /// List the connections in the Conntrack
    List {
        #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
}

#[derive(Clone, Subcommand, Debug)]
pub enum PolicyCommands {
    /// List the policies currently enforced
    List {
        #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
}
