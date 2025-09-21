use std::sync::{LazyLock, RwLock};

use prometheus_client::registry::Registry;

pub static REGISTRY: LazyLock<RwLock<Registry>> =
    LazyLock::new(|| RwLock::new(Registry::with_prefix("mesh_cni")));
