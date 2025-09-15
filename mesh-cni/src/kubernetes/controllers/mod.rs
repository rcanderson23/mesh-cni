use tokio::time::Duration;

pub mod bpf_service;
pub mod ip;
pub mod service;
pub mod utils;

const DEFAULT_REQUEUE_DURATION: Duration = Duration::from_secs(300);
