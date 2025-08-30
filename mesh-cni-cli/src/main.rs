mod cli;
mod client;
mod ip;
mod service;

use crate::cli::Cli;
use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        crate::cli::Commands::Ip(ip_commands) => ip::run(ip_commands).await?,
        crate::cli::Commands::Service(service_commands) => service::run(service_commands).await?,
    };
    Ok(())
}

// TODO: setup logging with config flag
fn _setup_subscriber(_telemetry_endpoint: Option<&str>) {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mesh_cni_cli=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}
