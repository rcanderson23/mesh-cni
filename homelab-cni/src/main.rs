use clap::Parser;
use homelab_cni::config::Cli;
use homelab_cni::{Result, controller, kubernetes};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> Result<()> {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.

    let cli = Cli::parse();
    match cli.command {
        homelab_cni::config::Commands::Controller(controller_args) => {
            setup_subscriber(None);
            let kube_state = kubernetes::start_kube_watchers().await?;
            controller::start(controller_args, kube_state).await?
        }
    }
    Ok(())
}

// TODO: setup telemetry endpoint option
fn setup_subscriber(_telemetry_endpoint: Option<&str>) {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "homelab_cni=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}
