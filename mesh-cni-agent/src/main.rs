use std::sync::Arc;

use clap::Parser;
use mesh_cni_agent::{Result, agent, cni, config::Cli, http};
use tokio::task::JoinError;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        mesh_cni_agent::config::Commands::Controller(controller_args) => {
            setup_subscriber(None);

            cni::ensure_cni_preconditions(&controller_args)?;

            let metrics_state = Arc::new(http::State::default());
            let cancel = tokio_util::sync::CancellationToken::new();
            let mut metrics_handle = tokio::spawn(http::serve(
                controller_args.metrics_address,
                metrics_state,
                cancel.child_token(),
            ));
            let mut agent_handle =
                tokio::spawn(agent::start(controller_args, cancel.child_token()));
            let mut shutdown_handle = tokio::spawn(async move { shutdown_signal().await });
            // watch for shutdown and errors
            tokio::select! {
                h = &mut metrics_handle => exit("metrics", h),
                h = &mut agent_handle => exit("agent", h),
                _ = &mut shutdown_handle => {
                        cancel.cancel();
                        let (metrics, agent) = tokio::join!(metrics_handle, agent_handle);
                        if let Err(m) = metrics {
                            error!("metrics exited with error: {}", m.to_string());
                        }
                        if let Err(s) = agent {
                            error!("agent exited with error: {}", s.to_string());
                        }
                    },
            };
            info!("Exiting...");
        }
    }
    Ok(())
}

// TODO: setup telemetry endpoint option
fn setup_subscriber(_telemetry_endpoint: Option<&str>) {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mesh_cni_agent=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };
    tokio::select! {
        _ = ctrl_c => {
          info!("captured ctrl_c signal");
        },
        _ = terminate => {},
    }
}

fn exit(task: &str, out: Result<Result<()>, JoinError>) {
    match out {
        Ok(Ok(_)) => {
            info!("{task} exited")
        }
        Ok(Err(e)) => {
            error!("{task} failed with error: {e}")
        }
        Err(e) => {
            error!("{task} task failed to complete: {e}")
        }
    }
}
