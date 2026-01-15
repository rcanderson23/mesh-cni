use tokio::time::Duration;

pub mod bpf_service;

mod ip;
pub use ip::start_ip_controllers;
mod metrics;
pub(crate) mod utils;

const DEFAULT_REQUEUE_DURATION: Duration = Duration::from_secs(300);
