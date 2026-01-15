pub mod cluster;
pub mod controllers;
pub mod node;
pub mod service;
pub mod state;

use std::collections::BTreeMap;
use std::collections::HashMap;

const LABEL_MESH_CLUSTER_ID: &str = "mesh-cni.dev/cluster-id";

pub type ClusterId = u32;

// TODO: does this actually need seperateion between types of labels or should
// there be some prefixing to denote the label origin?
#[derive(Eq, Hash, PartialEq, Clone)]
pub struct Labels {
    pub namespace_labels: BTreeMap<String, String>,
    pub pod_labels: BTreeMap<String, String>,
    pub mesh_labels: BTreeMap<&'static str, String>,
}

impl Labels {
    pub fn to_hashmap(&self) -> HashMap<String, String> {
        let mut map = HashMap::default();
        for (k, v) in self.namespace_labels.iter() {
            map.insert(k.to_owned(), v.to_owned());
        }
        for (k, v) in self.pod_labels.iter() {
            map.insert(k.to_owned(), v.to_owned());
        }
        for (k, v) in self.mesh_labels.iter() {
            map.insert(k.to_string(), v.to_owned());
        }
        map
    }
}
