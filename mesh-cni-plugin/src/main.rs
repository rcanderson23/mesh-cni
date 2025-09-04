use std::io::Read;
use std::process::ExitCode;

use clap::Parser;
use mesh_cni_plugin::delete::delete;
use mesh_cni_plugin::types::Input;
use mesh_cni_plugin::{CNI_VERSION, add::add};
use mesh_cni_plugin::{Result, config::Args};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn main() -> ExitCode {
    let _guard = setup_logging();
    let args = Args::parse();
    let resp = match args.command {
        mesh_cni_plugin::config::Command::Add => {
            let input = read_input();
            match input {
                Ok(input) => add(&args, input),
                Err(e) => e.into_response(CNI_VERSION),
            }
        }
        mesh_cni_plugin::config::Command::Delete => {
            let input = read_input();
            match input {
                Ok(input) => delete(&args, input),
                Err(e) => e.into_response(CNI_VERSION),
            }
        }
        mesh_cni_plugin::config::Command::Check => todo!(),
        mesh_cni_plugin::config::Command::Status => todo!(),
        mesh_cni_plugin::config::Command::Version => todo!(),
        mesh_cni_plugin::config::Command::Gc => todo!(),
    };

    resp.write_out()
}

fn read_input() -> Result<Input> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(serde_json::from_str(&buf)?)
}

fn setup_logging() -> WorkerGuard {
    let file_appender = tracing_appender::rolling::daily("/var/log/mesh-cni", "cni.log");
    let (nonblocking, guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mesh_cni=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(nonblocking))
        .init();
    guard
}
