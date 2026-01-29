use std::{collections::BTreeMap, str::FromStr};

use k8s_openapi::{
    api::networking::v1::{
        NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyIngressRule, NetworkPolicyPeer,
        NetworkPolicySpec,
    },
    apimachinery::pkg::apis::meta::v1::LabelSelector,
};
use kube::{
    ResourceExt,
    core::{Selector, SelectorExt},
};
use mesh_cni_crds::v1alpha1::identity::Identity;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PolicyType {
    Ingress,
    Egress,
}

impl FromStr for PolicyType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Ingress" | "ingress" => Ok(Self::Ingress),
            "Egress" | "egress" => Ok(Self::Egress),
            _ => Err("Unknown policy type"),
        }
    }
}

pub(crate) fn policy_selects_identity(policy: &NetworkPolicy, identity: &Identity) -> bool {
    let Some(policy_ns) = policy.namespace() else {
        return false;
    };
    let Some(identity_ns) = identity.namespace() else {
        return false;
    };
    if policy_ns != identity_ns {
        return false;
    }

    let Some(spec) = &policy.spec else {
        return false;
    };

    let Some(policy_pod_selector) = spec.pod_selector.to_owned() else {
        return false;
    };

    label_selector_matches(&policy_pod_selector, &identity.spec.pod_labels)
}

fn peers_select_identity(peers: Option<&Vec<NetworkPolicyPeer>>, identity: &Identity) -> bool {
    match peers {
        None => true,
        Some(peers) if peers.is_empty() => true,
        Some(peers) => peers
            .iter()
            .any(|peer| peer_selects_identity(peer, identity)),
    }
}

pub(crate) fn peer_selects_identity(peer: &NetworkPolicyPeer, identity: &Identity) -> bool {
    if peer.ip_block.is_some() && peer.pod_selector.is_none() && peer.namespace_selector.is_none() {
        return false;
    }

    if let Some(selector) = &peer.namespace_selector
        && !label_selector_matches(selector, &identity.spec.namespace_labels)
    {
        return false;
    }

    if let Some(selector) = &peer.pod_selector
        && !label_selector_matches(selector, &identity.spec.pod_labels)
    {
        return false;
    }

    peer.pod_selector.is_some() || peer.namespace_selector.is_some()
}

pub(crate) fn label_selector_matches(
    selector: &LabelSelector,
    labels: &BTreeMap<String, String>,
) -> bool {
    let Ok(selector) = Selector::try_from(selector.clone()) else {
        return false;
    };
    selector.matches(labels)
}

pub fn ingress_rules_select_identity(
    identity: &Identity,
    policy: &NetworkPolicy,
) -> Vec<NetworkPolicyIngressRule> {
    let Some(spec) = &policy.spec else {
        return vec![];
    };

    if !policy_affects_type(spec, PolicyType::Ingress) {
        return vec![];
    }

    let Some(rules) = &spec.ingress else {
        return vec![];
    };

    rules
        .iter()
        .filter(|rule| {
            let peers = rule.from.as_ref();
            peers_select_identity(peers, identity)
        })
        .cloned()
        .collect()
}

pub fn egress_rules_select_identity(
    identity: &Identity,
    policy: &NetworkPolicy,
) -> Vec<NetworkPolicyEgressRule> {
    let Some(spec) = &policy.spec else {
        return vec![];
    };

    if !policy_affects_type(spec, PolicyType::Egress) {
        return vec![];
    }

    let Some(rules) = &spec.egress else {
        return vec![];
    };
    rules
        .iter()
        .filter(|rule| {
            let peers = rule.to.as_ref();
            peers_select_identity(peers, identity)
        })
        .cloned()
        .collect()
}

pub(crate) fn policy_affects_type(spec: &NetworkPolicySpec, policy_type: PolicyType) -> bool {
    let Some(policy_types) = &spec.policy_types else {
        return match policy_type {
            PolicyType::Ingress => spec.ingress.is_some() || spec.egress.is_none(),
            PolicyType::Egress => spec.egress.is_some(),
        };
    };
    policy_types.iter().any(|spec_policy_type| {
        if let Ok(spt) = PolicyType::from_str(spec_policy_type) {
            spt == policy_type
        } else {
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use k8s_openapi::{
        api::networking::v1::{IPBlock, NetworkPolicy, NetworkPolicyPeer, NetworkPolicySpec},
        apimachinery::pkg::apis::meta::v1::{LabelSelector, LabelSelectorRequirement},
    };
    use kube::api::ObjectMeta;
    use mesh_cni_crds::v1alpha1::identity::{Identity, IdentitySpec};

    use super::{peer_selects_identity, policy_selects_identity};

    fn make_identity() -> Identity {
        let mut pod_labels = BTreeMap::new();
        pod_labels.insert("app".into(), "demo".into());
        pod_labels.insert("tier".into(), "backend".into());

        let mut ns_labels = BTreeMap::new();
        ns_labels.insert("team".into(), "alpha".into());
        ns_labels.insert("env".into(), "prod".into());

        let spec = IdentitySpec {
            namespace_labels: ns_labels,
            pod_labels,
            id: 1,
        };

        Identity::new("ident-a", spec)
    }

    fn make_selector_eq(key: &str, value: &str) -> LabelSelector {
        let mut match_labels = BTreeMap::new();
        match_labels.insert(key.to_string(), value.to_string());
        LabelSelector {
            match_labels: Some(match_labels),
            match_expressions: None,
        }
    }

    fn make_selector_in(key: &str, values: &[&str]) -> LabelSelector {
        LabelSelector {
            match_labels: None,
            match_expressions: Some(vec![LabelSelectorRequirement {
                key: key.to_string(),
                operator: "In".to_string(),
                values: Some(values.iter().map(|v| v.to_string()).collect()),
            }]),
        }
    }

    fn make_policy(ns: &str, selector: Option<LabelSelector>) -> NetworkPolicy {
        NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("policy-a".into()),
                namespace: Some(ns.into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: selector,
                ..Default::default()
            }),
        }
    }

    #[test]
    fn peer_selects_identity_pod_selector_match() {
        let identity = make_identity();
        let peer = NetworkPolicyPeer {
            pod_selector: Some(make_selector_eq("app", "demo")),
            namespace_selector: None,
            ip_block: None,
        };

        assert!(peer_selects_identity(&peer, &identity));
    }

    #[test]
    fn peer_selects_identity_namespace_selector_match() {
        let identity = make_identity();
        let peer = NetworkPolicyPeer {
            pod_selector: None,
            namespace_selector: Some(make_selector_eq("team", "alpha")),
            ip_block: None,
        };

        assert!(peer_selects_identity(&peer, &identity));
    }

    #[test]
    fn peer_selects_identity_both_selectors_match() {
        let identity = make_identity();
        let peer = NetworkPolicyPeer {
            pod_selector: Some(make_selector_eq("tier", "backend")),
            namespace_selector: Some(make_selector_eq("env", "prod")),
            ip_block: None,
        };

        assert!(peer_selects_identity(&peer, &identity));
    }

    #[test]
    fn peer_selects_identity_pod_selector_mismatch() {
        let identity = make_identity();
        let peer = NetworkPolicyPeer {
            pod_selector: Some(make_selector_eq("app", "api")),
            namespace_selector: None,
            ip_block: None,
        };

        assert!(!peer_selects_identity(&peer, &identity));
    }

    #[test]
    fn peer_selects_identity_namespace_selector_mismatch() {
        let identity = make_identity();
        let peer = NetworkPolicyPeer {
            pod_selector: None,
            namespace_selector: Some(make_selector_eq("env", "dev")),
            ip_block: None,
        };

        assert!(!peer_selects_identity(&peer, &identity));
    }

    #[test]
    fn peer_selects_identity_both_selectors_namespace_mismatch() {
        let identity = make_identity();
        let peer = NetworkPolicyPeer {
            pod_selector: Some(make_selector_eq("app", "demo")),
            namespace_selector: Some(make_selector_eq("env", "dev")),
            ip_block: None,
        };

        assert!(!peer_selects_identity(&peer, &identity));
    }

    #[test]
    fn peer_selects_identity_ipblock_only_false() {
        let identity = make_identity();
        let peer = NetworkPolicyPeer {
            pod_selector: None,
            namespace_selector: None,
            ip_block: Some(IPBlock {
                cidr: "10.0.0.0/8".into(),
                except: None,
            }),
        };

        assert!(!peer_selects_identity(&peer, &identity));
    }

    #[test]
    fn peer_selects_identity_label_expression_match() {
        let identity = make_identity();
        let peer = NetworkPolicyPeer {
            pod_selector: Some(make_selector_in("tier", &["backend", "worker"])),
            namespace_selector: None,
            ip_block: None,
        };

        assert!(peer_selects_identity(&peer, &identity));
    }

    #[test]
    fn peer_selects_identity_label_expression_mismatch() {
        let identity = make_identity();
        let peer = NetworkPolicyPeer {
            pod_selector: Some(make_selector_in("tier", &["frontend"])),
            namespace_selector: None,
            ip_block: None,
        };

        assert!(!peer_selects_identity(&peer, &identity));
    }

    #[test]
    fn policy_selects_identity_same_namespace_match() {
        let identity = make_identity();
        let mut identity = identity;
        identity.metadata.namespace = Some("ns-a".into());

        let policy = make_policy("ns-a", Some(make_selector_eq("app", "demo")));
        assert!(policy_selects_identity(&policy, &identity));
    }

    #[test]
    fn policy_selects_identity_namespace_mismatch() {
        let identity = make_identity();
        let mut identity = identity;
        identity.metadata.namespace = Some("ns-a".into());

        let policy = make_policy("ns-b", Some(make_selector_eq("app", "demo")));
        assert!(!policy_selects_identity(&policy, &identity));
    }

    #[test]
    fn policy_selects_identity_selector_mismatch() {
        let identity = make_identity();
        let mut identity = identity;
        identity.metadata.namespace = Some("ns-a".into());

        let policy = make_policy("ns-a", Some(make_selector_eq("app", "api")));
        assert!(!policy_selects_identity(&policy, &identity));
    }

    #[test]
    fn policy_selects_identity_missing_namespace_false() {
        let identity = make_identity();
        let policy = make_policy("ns-a", Some(make_selector_eq("app", "demo")));
        assert!(!policy_selects_identity(&policy, &identity));
    }
}
