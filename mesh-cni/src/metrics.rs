use std::sync::Arc;

use prometheus_client::registry::Registry;

#[derive(Clone)]
pub struct Metrics {
    pub registry: Arc<Registry>,
}

impl Default for Metrics {
    fn default() -> Self {
        let registry = Registry::with_prefix("homelab_cni");
        Self {
            registry: Arc::new(registry),
        }
    }
}
