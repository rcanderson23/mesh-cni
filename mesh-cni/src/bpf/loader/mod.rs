mod api;
mod state;

pub use state::State as LoaderState;

pub(crate) const INGRESS_TC_NAME: &str = "mesh_cni_ingress";
