use std::sync::Arc;

use prometheus_client::registry::Registry;

use crate::controller::metrics::ControllerMetrics;

#[derive(Clone)]
pub struct Metrics {
    pub controller: ControllerMetrics,
    pub registry: Arc<Registry>,
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::with_prefix("homelab_cni");
        let controller = ControllerMetrics::default().register(&mut registry);
        Self {
            registry: Arc::new(registry),
            controller,
        }
    }
}
