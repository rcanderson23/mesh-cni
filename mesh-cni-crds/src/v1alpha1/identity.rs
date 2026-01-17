use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Namespace, Pod};
use kube::{CustomResource, KubeSchema, ResourceExt};
use serde::{Deserialize, Serialize};

use mesh_cni_k8s_utils::sanitize_pod_labels;

#[derive(
    CustomResource, KubeSchema, Serialize, Deserialize, Default, PartialEq, Eq, Clone, Debug,
)]
#[kube(
    group = "mesh-cni.dev",
    version = "v1alpha1",
    kind = "Identity",
    derive = "Default",
    derive = "PartialEq",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct IdentitySpec {
    pub namespace_labels: BTreeMap<String, String>,
    pub pod_labels: BTreeMap<String, String>,
    pub id: u32,
}

impl Identity {
    pub fn pod_namespace_labels_match(&self, pod: &Pod, namespace: &Namespace) -> bool {
        let mut pod_labels = pod.labels().clone();
        sanitize_pod_labels(&mut pod_labels);

        let namespace_labels = namespace.labels();

        self.spec.pod_labels == pod_labels && *namespace_labels == self.spec.namespace_labels
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use k8s_openapi::api::core::v1::{Namespace, Pod};
    use kube::api::ObjectMeta;

    use super::{Identity, IdentitySpec};

    fn make_namespace(labels: BTreeMap<String, String>) -> Namespace {
        Namespace {
            metadata: ObjectMeta {
                name: Some("ns-a".into()),
                labels: Some(labels),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn make_pod(labels: BTreeMap<String, String>) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some("pod-a".into()),
                namespace: Some("ns-a".into()),
                labels: Some(labels),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_pod_namespace_labels_match_sanitizes_pod_labels() {
        let mut pod_labels = BTreeMap::new();
        pod_labels.insert("app".into(), "demo".into());
        pod_labels.insert("controller-revision-hash".into(), "remove-me".into());

        let mut ns_labels = BTreeMap::new();
        ns_labels.insert("env".into(), "test".into());

        let spec = IdentitySpec {
            namespace_labels: ns_labels.clone(),
            pod_labels: {
                let mut labels = BTreeMap::new();
                labels.insert("app".into(), "demo".into());
                labels
            },
            id: 1,
        };

        let identity = Identity::new("ident-a", spec);
        let pod = make_pod(pod_labels);
        let namespace = make_namespace(ns_labels);

        assert!(identity.pod_namespace_labels_match(&pod, &namespace));
    }

    #[test]
    fn test_pod_namespace_labels_match_namespace_mismatch() {
        let mut pod_labels = BTreeMap::new();
        pod_labels.insert("app".into(), "demo".into());

        let mut ns_labels = BTreeMap::new();
        ns_labels.insert("env".into(), "test".into());

        let mut other_ns_labels = BTreeMap::new();
        other_ns_labels.insert("env".into(), "prod".into());

        let spec = IdentitySpec {
            namespace_labels: ns_labels,
            pod_labels,
            id: 1,
        };

        let identity = Identity::new("ident-a", spec);
        let pod = make_pod({
            let mut labels = BTreeMap::new();
            labels.insert("app".into(), "demo".into());
            labels
        });
        let namespace = make_namespace(other_ns_labels);

        assert!(!identity.pod_namespace_labels_match(&pod, &namespace));
    }
}
