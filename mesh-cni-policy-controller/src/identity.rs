use core::hash::Hasher;
use std::sync::Arc;

use ahash::{HashMap, HashSet};
use k8s_openapi::{
    api::{
        core::v1::{ContainerPort, Pod},
        networking::v1::{NetworkPolicy, NetworkPolicyPeer, NetworkPolicyPort},
    },
    apimachinery::pkg::util::intstr::IntOrString,
};
use kube::{ResourceExt, runtime::controller::Action};
use mesh_cni_crds::v1alpha1::identity::Identity;
use mesh_cni_ebpf_common::{
    IdentityId,
    policy::{
        ANY_ID, ANY_PORT, Action as PolicyAction, PolicyDirection, PolicyIndexKey, PolicyProtocol,
        PolicyRuleKey, PolicyValue, RULESET_NONE,
    },
};

use crate::{
    PolicyControllerBpf, PolicyControllerExt, Result,
    context::{Context, RulesetId},
    controller::DEFAULT_REQUEUE_DURATION,
    selector::{PolicyType, peer_selects_identity, policy_affects_type, policy_selects_identity},
};

impl<P: PolicyControllerBpf> PolicyControllerExt<P> for Identity {
    // Policy enforcement is broken up into two seperate BPF maps. The first map is keyed on
    // the src_id, dst_id, and policy direction returning a ruleset_id. This ruleset_id
    // can be combined with protocol and destination port to determine the desired action and
    // allowing wildcard checks on port and proto. This ideally cuts down the number of BPF map
    // checks for a new flow as well as allowing for re-usable rulesets reducing map size.
    // We compute per-peer ingress/egress rules, resolve named ports against the peer
    // identity's pods (when used in the policy), inject default-deny for directions with
    // policyTypes but no allow rules, then diff desired vs current index entries and update
    // BPF maps while releasing unused rulesets.
    fn reconcile(&self, ctx: Arc<Context<P>>) -> Result<Action> {
        let policy_state = ctx.policy_store.state();
        let selected_netpols: Vec<&Arc<NetworkPolicy>> = policy_state
            .iter()
            .filter(|np| policy_selects_identity(np, self))
            .collect();

        let identity_id = self.spec.id;
        let index_state = ctx.policy_bpf_state.index_state()?;
        let identities = ctx.identity_store.state();
        let pods = ctx.pod_store.state();
        let identity_by_id: HashMap<u32, Arc<Identity>> = identities
            .iter()
            .map(|id| (id.spec.id, id.clone()))
            .collect();
        let mut desired_index: HashMap<PolicyIndexKey, u32> = HashMap::default();
        let mut written_rulesets: HashSet<u32> = HashSet::default();
        let mut has_ingress_policy = false;
        let mut has_egress_policy = false;

        if selected_netpols.is_empty() {
            desired_index.insert(
                PolicyIndexKey {
                    src_id: identity_id,
                    dst_id: ANY_ID,
                    direction: PolicyDirection::any_u8(),
                    _pad: [0; 3],
                },
                RULESET_NONE,
            );
        } else {
            let mut ingress_rules: HashMap<u32, Vec<RuleSpec>> = HashMap::default();
            let mut egress_rules: HashMap<u32, Vec<RuleSpec>> = HashMap::default();

            for policy in &selected_netpols {
                let Some(spec) = &policy.spec else {
                    continue;
                };

                let Some(policy_ns) = policy.namespace() else {
                    continue;
                };

                if policy_affects_type(spec, PolicyType::Ingress) {
                    has_ingress_policy = true;
                    let rules = spec.ingress.as_deref().unwrap_or(&[]);
                    for rule in rules {
                        let peer_ids =
                            peer_ids_for_rule(&policy_ns, rule.from.as_ref(), &identities);
                        for peer_id in peer_ids {
                            let rule_specs = rule_specs_for_peer(
                                peer_id,
                                self,
                                &identity_by_id,
                                &pods,
                                rule.ports.as_ref(),
                            );
                            add_rule_specs(&mut ingress_rules, &[peer_id], &rule_specs);
                        }
                    }
                }

                if policy_affects_type(spec, PolicyType::Egress) {
                    has_egress_policy = true;
                    let rules = spec.egress.as_deref().unwrap_or(&[]);
                    for rule in rules {
                        let peer_ids = peer_ids_for_rule(&policy_ns, rule.to.as_ref(), &identities);
                        for peer_id in peer_ids {
                            let rule_specs = rule_specs_for_peer(
                                peer_id,
                                self,
                                &identity_by_id,
                                &pods,
                                rule.ports.as_ref(),
                            );
                            add_rule_specs(&mut egress_rules, &[peer_id], &rule_specs);
                        }
                    }
                }
            }

            if has_ingress_policy {
                add_rule_specs(&mut ingress_rules, &[ANY_ID], &[RuleSpec::deny_any()]);
            }

            for (peer_id, rule_specs) in ingress_rules {
                if rule_specs.is_empty() {
                    continue;
                }
                let (ruleset_id, ruleset_entries) =
                    build_ruleset(rule_specs.to_vec(), &ctx.ruleset_state);
                if written_rulesets.insert(ruleset_id) {
                    for (key, value) in &ruleset_entries {
                        ctx.policy_bpf_state.update_rule(*key, *value)?;
                    }
                }
                desired_index.insert(
                    PolicyIndexKey {
                        src_id: peer_id,
                        dst_id: identity_id,
                        direction: PolicyDirection::ingress_u8(),
                        _pad: [0; 3],
                    },
                    ruleset_id,
                );
            }

            if has_egress_policy {
                add_rule_specs(&mut egress_rules, &[ANY_ID], &[RuleSpec::deny_any()]);
            }

            for (peer_id, rule_specs) in egress_rules {
                if rule_specs.is_empty() {
                    continue;
                }
                let (ruleset_id, ruleset_entries) =
                    build_ruleset(rule_specs.to_vec(), &ctx.ruleset_state);
                if written_rulesets.insert(ruleset_id) {
                    for (key, value) in &ruleset_entries {
                        ctx.policy_bpf_state.update_rule(*key, *value)?;
                    }
                }
                desired_index.insert(
                    PolicyIndexKey {
                        src_id: identity_id,
                        dst_id: peer_id,
                        direction: PolicyDirection::egress_u8(),
                        _pad: [0; 3],
                    },
                    ruleset_id,
                );
            }
        }

        let current_index: HashMap<PolicyIndexKey, u32> = index_state
            .iter()
            .filter(|(key, _)| identity_key_applies(identity_id, key))
            .map(|(key, value)| (*key, *value))
            .collect();

        for (key, current_ruleset_id) in &current_index {
            match desired_index.get(key) {
                Some(desired_ruleset_id) if *desired_ruleset_id == *current_ruleset_id => {}
                Some(desired_ruleset_id) => {
                    ctx.policy_bpf_state
                        .update_index(*key, *desired_ruleset_id)?;
                    release_ruleset_if_unused(&ctx, *current_ruleset_id)?;
                }
                None => {
                    ctx.policy_bpf_state.delete_index(key)?;
                    release_ruleset_if_unused(&ctx, *current_ruleset_id)?;
                }
            }
        }

        for (key, ruleset_id) in desired_index {
            if current_index.contains_key(&key) {
                continue;
            }
            ctx.policy_bpf_state.update_index(key, ruleset_id)?;
        }

        Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct RuleSpec {
    proto: u8,
    port: u16,
    action: u8,
}

impl Default for RuleSpec {
    fn default() -> Self {
        Self {
            proto: PolicyProtocol::any_u8(),
            port: ANY_PORT,
            action: PolicyAction::allow_u8(),
        }
    }
}

impl RuleSpec {
    fn deny_any() -> Self {
        Self {
            proto: PolicyProtocol::any_u8(),
            port: ANY_PORT,
            action: PolicyAction::deny_u8(),
        }
    }
}

fn rule_specs_from_ports(
    identity: &Identity,
    pods: &[Arc<Pod>],
    ports: Option<&Vec<NetworkPolicyPort>>,
) -> Vec<RuleSpec> {
    let ports = match ports {
        None => return vec![RuleSpec::default()],
        Some(p) if p.is_empty() => return vec![RuleSpec::default()],
        Some(p) => p,
    };

    let mut specs = Vec::new();
    for port in ports {
        let proto = match port.protocol.as_deref() {
            None => PolicyProtocol::tcp_u8(),
            Some("TCP") => PolicyProtocol::tcp_u8(),
            Some("UDP") => PolicyProtocol::udp_u8(),
            Some("SCTP") => PolicyProtocol::sctp_u8(),
            Some(_) => continue,
        };

        let Some(port_value) = &port.port else {
            specs.push(RuleSpec {
                proto,
                port: ANY_PORT,
                action: PolicyAction::allow_u8(),
            });
            continue;
        };

        match port_value {
            IntOrString::Int(port_value) => {
                if port.end_port.is_some() {
                    continue;
                }

                let Ok(port_value) = u16::try_from(*port_value) else {
                    continue;
                };

                specs.push(RuleSpec {
                    proto,
                    port: port_value,
                    action: PolicyAction::allow_u8(),
                });
            }
            IntOrString::String(port_name) => {
                let resolved_ports = resolve_named_ports(identity, pods, port_name, proto);
                for resolved_port in resolved_ports {
                    specs.push(RuleSpec {
                        proto,
                        port: resolved_port,
                        action: PolicyAction::allow_u8(),
                    });
                }
            }
        }
    }

    specs
}

fn rule_specs_for_peer(
    peer_id: u32,
    self_identity: &Identity,
    identities: &HashMap<u32, Arc<Identity>>,
    pods: &[Arc<Pod>],
    ports: Option<&Vec<NetworkPolicyPort>>,
) -> Vec<RuleSpec> {
    if peer_id == ANY_ID {
        return rule_specs_from_ports(self_identity, pods, ports);
    }

    let Some(peer_identity) = identities.get(&peer_id) else {
        return Vec::new();
    };

    rule_specs_from_ports(peer_identity, pods, ports)
}

fn resolve_named_ports(
    identity: &Identity,
    pods: &[Arc<Pod>],
    port_name: &str,
    proto: u8,
) -> Vec<u16> {
    let identity_ns = match identity.namespace() {
        Some(ns) => ns,
        None => return Vec::new(),
    };

    let mut resolved = Vec::new();
    for pod in pods {
        if pod.namespace().as_deref() != Some(identity_ns.as_str()) {
            continue;
        }
        if !labels_match_identity(identity, pod) {
            continue;
        }

        let Some(spec) = &pod.spec else {
            continue;
        };

        for container in &spec.containers {
            let Some(ports) = &container.ports else {
                continue;
            };
            for container_port in ports {
                if container_port.name.as_deref() != Some(port_name) {
                    continue;
                }
                if !container_port_matches_protocol(container_port, proto) {
                    continue;
                }
                let Ok(port) = u16::try_from(container_port.container_port) else {
                    continue;
                };
                resolved.push(port);
            }
        }
    }

    resolved
}

fn labels_match_identity(identity: &Identity, pod: &Pod) -> bool {
    let mut labels = pod.labels().clone();
    mesh_cni_k8s_utils::sanitize_pod_labels(&mut labels);
    identity.spec.pod_labels == labels
}

fn container_port_matches_protocol(container_port: &ContainerPort, proto: u8) -> bool {
    let declared = match container_port.protocol.as_deref() {
        None => PolicyProtocol::tcp_u8(),
        Some("TCP") => PolicyProtocol::tcp_u8(),
        Some("UDP") => PolicyProtocol::udp_u8(),
        Some("SCTP") => PolicyProtocol::sctp_u8(),
        Some(_) => return false,
    };

    proto == declared
}

fn peer_ids_for_rule(
    policy_ns: &str,
    peers: Option<&Vec<NetworkPolicyPeer>>,
    identities: &[Arc<Identity>],
) -> Vec<u32> {
    let Some(peers) = peers else {
        return vec![ANY_ID];
    };
    if peers.is_empty() {
        return vec![ANY_ID];
    }

    let mut ids = Vec::new();
    for peer in peers {
        let same_namespace_only = peer.namespace_selector.is_none() && peer.pod_selector.is_some();

        for identity in identities {
            let Some(identity_ns) = identity.namespace() else {
                continue;
            };
            if same_namespace_only && Some(identity_ns.as_str()) != Some(policy_ns) {
                continue;
            }

            if peer_selects_identity(peer, identity) {
                ids.push(identity.spec.id);
            }
        }
    }

    ids
}

fn add_rule_specs(
    map: &mut HashMap<u32, Vec<RuleSpec>>,
    peer_ids: &[u32],
    rule_specs: &[RuleSpec],
) {
    for peer_id in peer_ids {
        let entry = map.entry(*peer_id).or_default();
        entry.extend_from_slice(rule_specs);
    }
}

fn build_ruleset(
    mut rules: Vec<RuleSpec>,
    ruleset_state: &crate::context::RulesetState,
) -> (RulesetId, Vec<(PolicyRuleKey, PolicyValue)>) {
    rules.sort_by_key(|rule| (rule.proto, rule.port, rule.action));
    rules.dedup();

    let mut hasher = ahash::AHasher::default();
    for rule in &rules {
        hasher.write_u8(rule.proto);
        hasher.write_u16(rule.port);
        hasher.write_u8(rule.action);
    }
    let hash = hasher.finish();

    let ruleset_id = ruleset_state.acquire_ruleset(
        hash,
        rules
            .iter()
            .map(|rule| {
                (
                    PolicyRuleKey {
                        ruleset_id: RULESET_NONE,
                        proto: rule.proto,
                        _pad0: [0; 3],
                        port: rule.port,
                        _pad1: [0; 2],
                    },
                    PolicyValue {
                        action: rule.action,
                    },
                )
            })
            .collect(),
    );

    let ruleset_entries = rules
        .into_iter()
        .map(|rule| {
            (
                PolicyRuleKey {
                    ruleset_id,
                    proto: rule.proto,
                    _pad0: [0; 3],
                    port: rule.port,
                    _pad1: [0; 2],
                },
                PolicyValue {
                    action: rule.action,
                },
            )
        })
        .collect();

    (ruleset_id, ruleset_entries)
}

fn identity_key_applies(identity_id: IdentityId, key: &PolicyIndexKey) -> bool {
    match PolicyDirection::from(key.direction) {
        PolicyDirection::Ingress => key.dst_id == identity_id,
        PolicyDirection::Egress => key.src_id == identity_id,
        PolicyDirection::Any => key.src_id == identity_id,
    }
}

fn release_ruleset_if_unused<P: PolicyControllerBpf>(
    ctx: &Context<P>,
    ruleset_id: RulesetId,
) -> Result<()> {
    if ruleset_id == RULESET_NONE {
        return Ok(());
    }
    if let Some(rules) = ctx.ruleset_state.release_ruleset(ruleset_id) {
        for (key, _) in rules {
            ctx.policy_bpf_state.delete_rule(&key)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, hash::Hash, sync::Mutex};

    use k8s_openapi::{
        api::{
            core::v1::{Container, ContainerPort, Pod, PodSpec},
            networking::v1::{
                NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyIngressRule,
                NetworkPolicyPort, NetworkPolicySpec,
            },
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    };
    use kube::{
        api::ObjectMeta,
        runtime::{
            reflector::{
                Lookup,
                store::{Writer, store},
            },
            watcher,
        },
    };
    use mesh_cni_crds::v1alpha1::identity::IdentitySpec;

    use super::*;
    use crate::{
        Result,
        context::{Context, RulesetState},
    };

    struct TestPolicyBpfState {
        index: Mutex<HashMap<PolicyIndexKey, u32>>,
        ruleset: Mutex<HashMap<PolicyRuleKey, PolicyValue>>,
    }

    impl TestPolicyBpfState {
        fn new() -> Self {
            Self {
                index: Mutex::new(HashMap::default()),
                ruleset: Mutex::new(HashMap::default()),
            }
        }
    }

    impl PolicyControllerBpf for TestPolicyBpfState {
        fn update_index(&self, key: PolicyIndexKey, ruleset_id: u32) -> Result<()> {
            self.index.lock().unwrap().insert(key, ruleset_id);
            Ok(())
        }

        fn delete_index(&self, key: &PolicyIndexKey) -> Result<()> {
            self.index.lock().unwrap().remove(key);
            Ok(())
        }

        fn update_rule(&self, key: PolicyRuleKey, value: PolicyValue) -> Result<()> {
            self.ruleset.lock().unwrap().insert(key, value);
            Ok(())
        }

        fn delete_rule(&self, key: &PolicyRuleKey) -> Result<()> {
            self.ruleset.lock().unwrap().remove(key);
            Ok(())
        }

        fn index_state(&self) -> Result<HashMap<PolicyIndexKey, u32>> {
            Ok(self.index.lock().unwrap().clone())
        }

        fn ruleset_state(&self) -> Result<HashMap<PolicyRuleKey, PolicyValue>> {
            Ok(self.ruleset.lock().unwrap().clone())
        }
    }

    fn insert<K: Clone + Lookup + 'static>(writer: &mut Writer<K>, obj: K)
    where
        K::DynamicType: Eq + Hash + Clone,
    {
        writer.apply_watcher_event(&watcher::Event::Apply(obj));
    }

    #[test]
    fn reconcile_populates_rules_for_named_ports() {
        let identity = Identity::new(
            "ident-a",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                },
                id: 10,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("ns-a".into());

        let pod_a = Pod {
            metadata: ObjectMeta {
                name: Some("pod-a".into()),
                namespace: Some("ns-a".into()),
                labels: Some({
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                }),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: "app".into(),
                    ports: Some(vec![ContainerPort {
                        name: Some("http".into()),
                        container_port: 8080,
                        protocol: Some("TCP".into()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        let pod_b = Pod {
            metadata: ObjectMeta {
                name: Some("pod-b".into()),
                namespace: Some("ns-a".into()),
                labels: Some({
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                }),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: "app".into(),
                    ports: Some(vec![ContainerPort {
                        name: Some("http".into()),
                        container_port: 8081,
                        protocol: Some("TCP".into()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-http".into()),
                namespace: Some("ns-a".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("app".into(), "demo".into());
                        labels
                    }),
                    ..Default::default()
                }),
                ingress: Some(vec![NetworkPolicyIngressRule {
                    ports: Some(vec![NetworkPolicyPort {
                        protocol: Some("TCP".into()),
                        port: Some(IntOrString::String("http".into())),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        };

        let (pod_store, mut pod_writer) = store::<Pod>();
        let (policy_store, mut policy_writer) = store::<NetworkPolicy>();
        let (identity_store, mut identity_writer) = store::<Identity>();

        insert(&mut pod_writer, pod_a);
        insert(&mut pod_writer, pod_b);
        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, identity.clone());

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        identity.reconcile(ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let idx_key = PolicyIndexKey {
            src_id: ANY_ID,
            dst_id: 10,
            direction: PolicyDirection::ingress_u8(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&idx_key).expect("expected index entry");
        assert_ne!(ruleset_id, RULESET_NONE);

        let rule_key_a = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::tcp_u8(),
            _pad0: [0; 3],
            port: 8080,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key_a).expect("expected ruleset entry");
        assert_eq!(rule.action, PolicyAction::allow_u8());

        let rule_key_b = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::tcp_u8(),
            _pad0: [0; 3],
            port: 8081,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key_b).expect("expected ruleset entry");
        assert_eq!(rule.action, PolicyAction::allow_u8());
    }

    #[test]
    fn reconcile_defaults_to_allow_when_no_policies_select_identity() {
        let identity = Identity::new(
            "ident-a",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                },
                id: 42,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("ns-a".into());

        let (pod_store, _pod_writer) = store::<Pod>();
        let (policy_store, _policy_writer) = store::<NetworkPolicy>();
        let (identity_store, mut identity_writer) = store::<Identity>();

        insert(&mut identity_writer, identity.clone());

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        identity.reconcile(ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let idx_key = PolicyIndexKey {
            src_id: 42,
            dst_id: ANY_ID,
            direction: PolicyDirection::any_u8(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&idx_key).expect("expected default allow entry");
        assert_eq!(ruleset_id, RULESET_NONE);
        assert!(rules.is_empty());
    }

    #[test]
    fn reconcile_ingress_empty_from_uses_any_id() {
        let identity = Identity::new(
            "ident-a",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                },
                id: 7,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("ns-a".into());

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-any".into()),
                namespace: Some("ns-a".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("app".into(), "demo".into());
                        labels
                    }),
                    ..Default::default()
                }),
                ingress: Some(vec![NetworkPolicyIngressRule {
                    from: Some(vec![]),
                    ports: Some(vec![NetworkPolicyPort {
                        protocol: Some("TCP".into()),
                        port: Some(IntOrString::Int(80)),
                        ..Default::default()
                    }]),
                }]),
                ..Default::default()
            }),
        };

        let (pod_store, _pod_writer) = store::<Pod>();
        let (policy_store, mut policy_writer) = store::<NetworkPolicy>();
        let (identity_store, mut identity_writer) = store::<Identity>();

        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, identity.clone());

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        identity.reconcile(ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();
        let idx_key = PolicyIndexKey {
            src_id: ANY_ID,
            dst_id: 7,
            direction: PolicyDirection::ingress_u8(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&idx_key).expect("expected any-id ingress entry");
        assert_ne!(ruleset_id, RULESET_NONE);
        let rule_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::tcp_u8(),
            _pad0: [0; 3],
            port: 80,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key).expect("expected ruleset entry");
        assert_eq!(rule.action, PolicyAction::allow_u8());
    }

    #[test]
    fn reconcile_ingress_policy_type_without_rules_defaults_to_deny() {
        let identity = Identity::new(
            "ident-a",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                },
                id: 9,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("ns-a".into());

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("deny-all".into()),
                namespace: Some("ns-a".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("app".into(), "demo".into());
                        labels
                    }),
                    ..Default::default()
                }),
                policy_types: Some(vec!["Ingress".into()]),
                ..Default::default()
            }),
        };

        let (pod_store, _pod_writer) = store::<Pod>();
        let (policy_store, mut policy_writer) = store::<NetworkPolicy>();
        let (identity_store, mut identity_writer) = store::<Identity>();

        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, identity.clone());

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        identity.reconcile(ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let idx_key = PolicyIndexKey {
            src_id: ANY_ID,
            dst_id: 9,
            direction: PolicyDirection::ingress_u8(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&idx_key).expect("expected ingress deny entry");
        assert_ne!(ruleset_id, RULESET_NONE);

        let rule_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::any_u8(),
            _pad0: [0; 3],
            port: ANY_PORT,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key).expect("expected deny rule");
        assert_eq!(rule.action, PolicyAction::deny_u8());
    }

    #[test]
    fn reconcile_egress_empty_to_uses_any_id() {
        let identity = Identity::new(
            "ident-a",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                },
                id: 11,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("ns-a".into());

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-egress".into()),
                namespace: Some("ns-a".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("app".into(), "demo".into());
                        labels
                    }),
                    ..Default::default()
                }),
                egress: Some(vec![NetworkPolicyEgressRule {
                    to: Some(vec![]),
                    ports: Some(vec![NetworkPolicyPort {
                        protocol: Some("TCP".into()),
                        port: Some(IntOrString::Int(443)),
                        ..Default::default()
                    }]),
                }]),
                ..Default::default()
            }),
        };

        let (pod_store, _pod_writer) = store::<Pod>();
        let (policy_store, mut policy_writer) = store::<NetworkPolicy>();
        let (identity_store, mut identity_writer) = store::<Identity>();

        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, identity.clone());

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        identity.reconcile(ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let idx_key = PolicyIndexKey {
            src_id: 11,
            dst_id: ANY_ID,
            direction: PolicyDirection::egress_u8(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&idx_key).expect("expected any-id egress entry");
        assert_ne!(ruleset_id, RULESET_NONE);

        let rule_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::tcp_u8(),
            _pad0: [0; 3],
            port: 443,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key).expect("expected ruleset entry");
        assert_eq!(rule.action, PolicyAction::allow_u8());
    }

    #[test]
    fn reconcile_egress_policy_type_without_rules_defaults_to_deny() {
        let identity = Identity::new(
            "ident-a",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                },
                id: 12,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("ns-a".into());

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("deny-egress".into()),
                namespace: Some("ns-a".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("app".into(), "demo".into());
                        labels
                    }),
                    ..Default::default()
                }),
                policy_types: Some(vec!["Egress".into()]),
                ..Default::default()
            }),
        };

        let (pod_store, _pod_writer) = store::<Pod>();
        let (policy_store, mut policy_writer) = store::<NetworkPolicy>();
        let (identity_store, mut identity_writer) = store::<Identity>();

        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, identity.clone());

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        identity.reconcile(ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let idx_key = PolicyIndexKey {
            src_id: 12,
            dst_id: ANY_ID,
            direction: PolicyDirection::egress_u8(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&idx_key).expect("expected egress deny entry");
        assert_ne!(ruleset_id, RULESET_NONE);

        let rule_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::any_u8(),
            _pad0: [0; 3],
            port: ANY_PORT,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key).expect("expected deny rule");
        assert_eq!(rule.action, PolicyAction::deny_u8());
    }

    #[test]
    fn reconcile_egress_only_policy_does_not_add_ingress_default_deny() {
        let identity = Identity::new(
            "ident-a",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                },
                id: 13,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("ns-a".into());

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("egress-only".into()),
                namespace: Some("ns-a".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("app".into(), "demo".into());
                        labels
                    }),
                    ..Default::default()
                }),
                egress: Some(vec![NetworkPolicyEgressRule {
                    to: Some(vec![]),
                    ports: Some(vec![NetworkPolicyPort {
                        protocol: Some("TCP".into()),
                        port: Some(IntOrString::Int(53)),
                        ..Default::default()
                    }]),
                }]),
                ..Default::default()
            }),
        };

        let (pod_store, _pod_writer) = store::<Pod>();
        let (policy_store, mut policy_writer) = store::<NetworkPolicy>();
        let (identity_store, mut identity_writer) = store::<Identity>();

        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, identity.clone());

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        identity.reconcile(ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();

        let ingress_key = PolicyIndexKey {
            src_id: ANY_ID,
            dst_id: 13,
            direction: PolicyDirection::ingress_u8(),
            _pad: [0; 3],
        };
        assert!(!index.contains_key(&ingress_key));
    }

    #[test]
    fn reconcile_named_port_mismatch_emits_deny_rule() {
        let identity = Identity::new(
            "ident-a",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                },
                id: 14,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("ns-a".into());

        let pod = Pod {
            metadata: ObjectMeta {
                name: Some("pod-a".into()),
                namespace: Some("ns-a".into()),
                labels: Some({
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                }),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: "app".into(),
                    ports: Some(vec![ContainerPort {
                        name: Some("http".into()),
                        container_port: 8080,
                        protocol: Some("TCP".into()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-missing".into()),
                namespace: Some("ns-a".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("app".into(), "demo".into());
                        labels
                    }),
                    ..Default::default()
                }),
                ingress: Some(vec![NetworkPolicyIngressRule {
                    ports: Some(vec![NetworkPolicyPort {
                        protocol: Some("TCP".into()),
                        port: Some(IntOrString::String("missing".into())),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        };

        let (pod_store, mut pod_writer) = store::<Pod>();
        let (policy_store, mut policy_writer) = store::<NetworkPolicy>();
        let (identity_store, mut identity_writer) = store::<Identity>();

        insert(&mut pod_writer, pod);
        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, identity.clone());

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        identity.reconcile(ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let idx_key = PolicyIndexKey {
            src_id: ANY_ID,
            dst_id: 14,
            direction: PolicyDirection::ingress_u8(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&idx_key).expect("expected ingress entry");
        assert_ne!(ruleset_id, RULESET_NONE);

        let rule_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::any_u8(),
            _pad0: [0; 3],
            port: ANY_PORT,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key).expect("expected deny fallback");
        assert_eq!(rule.action, PolicyAction::deny_u8());
    }

    #[test]
    fn reconcile_namespace_selector_filters_peer_identities() {
        let identity = Identity::new(
            "ident-a",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                },
                id: 21,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("ns-a".into());

        let mut peer_allowed = Identity::new(
            "ident-b",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                },
                id: 22,
            },
        );
        peer_allowed.metadata.namespace = Some("ns-b".into());

        let mut peer_denied = Identity::new(
            "ident-c",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "dev".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                },
                id: 23,
            },
        );
        peer_denied.metadata.namespace = Some("ns-c".into());

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-from-prod".into()),
                namespace: Some("ns-a".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("app".into(), "demo".into());
                        labels
                    }),
                    ..Default::default()
                }),
                ingress: Some(vec![NetworkPolicyIngressRule {
                    from: Some(vec![NetworkPolicyPeer {
                        namespace_selector: Some(LabelSelector {
                            match_labels: Some({
                                let mut labels = BTreeMap::new();
                                labels.insert("env".into(), "prod".into());
                                labels
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }]),
                    ports: Some(vec![NetworkPolicyPort {
                        protocol: Some("TCP".into()),
                        port: Some(IntOrString::Int(80)),
                        ..Default::default()
                    }]),
                }]),
                ..Default::default()
            }),
        };

        let (pod_store, _pod_writer) = store::<Pod>();
        let (policy_store, mut policy_writer) = store::<NetworkPolicy>();
        let (identity_store, mut identity_writer) = store::<Identity>();

        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, identity.clone());
        insert(&mut identity_writer, peer_allowed.clone());
        insert(&mut identity_writer, peer_denied.clone());

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        identity.reconcile(ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let allowed_key = PolicyIndexKey {
            src_id: 22,
            dst_id: 21,
            direction: PolicyDirection::ingress_u8(),
            _pad: [0; 3],
        };
        let denied_key = PolicyIndexKey {
            src_id: 23,
            dst_id: 21,
            direction: PolicyDirection::ingress_u8(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&allowed_key).expect("expected allowed peer");
        assert!(!index.contains_key(&denied_key));

        let rule_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::tcp_u8(),
            _pad0: [0; 3],
            port: 80,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key).expect("expected allow rule");
        assert_eq!(rule.action, PolicyAction::allow_u8());
    }

    #[test]
    fn reconcile_namespace_selector_named_port_resolves_peer_ports() {
        let identity = Identity::new(
            "ident-a",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                },
                id: 41,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("ns-a".into());

        let mut peer = Identity::new(
            "ident-b",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("role".into(), "api".into());
                    labels
                },
                id: 42,
            },
        );
        peer.metadata.namespace = Some("ns-b".into());

        let pod = Pod {
            metadata: ObjectMeta {
                name: Some("pod-b".into()),
                namespace: Some("ns-b".into()),
                labels: Some({
                    let mut labels = BTreeMap::new();
                    labels.insert("role".into(), "api".into());
                    labels
                }),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: "api".into(),
                    ports: Some(vec![ContainerPort {
                        name: Some("http".into()),
                        container_port: 8080,
                        protocol: Some("TCP".into()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-from-prod".into()),
                namespace: Some("ns-a".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("app".into(), "demo".into());
                        labels
                    }),
                    ..Default::default()
                }),
                ingress: Some(vec![NetworkPolicyIngressRule {
                    from: Some(vec![NetworkPolicyPeer {
                        namespace_selector: Some(LabelSelector {
                            match_labels: Some({
                                let mut labels = BTreeMap::new();
                                labels.insert("env".into(), "prod".into());
                                labels
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }]),
                    ports: Some(vec![NetworkPolicyPort {
                        protocol: Some("TCP".into()),
                        port: Some(IntOrString::String("http".into())),
                        ..Default::default()
                    }]),
                }]),
                ..Default::default()
            }),
        };

        let (pod_store, mut pod_writer) = store::<Pod>();
        let (policy_store, mut policy_writer) = store::<NetworkPolicy>();
        let (identity_store, mut identity_writer) = store::<Identity>();

        insert(&mut pod_writer, pod);
        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, identity.clone());
        insert(&mut identity_writer, peer.clone());

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        identity.reconcile(ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let idx_key = PolicyIndexKey {
            src_id: 42,
            dst_id: 41,
            direction: PolicyDirection::ingress_u8(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&idx_key).expect("expected peer ingress entry");
        assert_ne!(ruleset_id, RULESET_NONE);

        let rule_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::tcp_u8(),
            _pad0: [0; 3],
            port: 8080,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key).expect("expected resolved named port");
        assert_eq!(rule.action, PolicyAction::allow_u8());
    }

    #[test]
    fn reconcile_updates_ruleset_and_removes_old_rules() {
        let identity = Identity::new(
            "ident-a",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "demo".into());
                    labels
                },
                id: 31,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("ns-a".into());

        let policy_v1 = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-port".into()),
                namespace: Some("ns-a".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("app".into(), "demo".into());
                        labels
                    }),
                    ..Default::default()
                }),
                ingress: Some(vec![NetworkPolicyIngressRule {
                    from: Some(vec![]),
                    ports: Some(vec![NetworkPolicyPort {
                        protocol: Some("TCP".into()),
                        port: Some(IntOrString::Int(80)),
                        ..Default::default()
                    }]),
                }]),
                ..Default::default()
            }),
        };

        let policy_v2 = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-port".into()),
                namespace: Some("ns-a".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("app".into(), "demo".into());
                        labels
                    }),
                    ..Default::default()
                }),
                ingress: Some(vec![NetworkPolicyIngressRule {
                    from: Some(vec![]),
                    ports: Some(vec![NetworkPolicyPort {
                        protocol: Some("TCP".into()),
                        port: Some(IntOrString::Int(81)),
                        ..Default::default()
                    }]),
                }]),
                ..Default::default()
            }),
        };

        let (pod_store, _pod_writer) = store::<Pod>();
        let (policy_store, mut policy_writer) = store::<NetworkPolicy>();
        let (identity_store, mut identity_writer) = store::<Identity>();

        insert(&mut policy_writer, policy_v1);
        insert(&mut identity_writer, identity.clone());

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        identity.reconcile(ctx.clone()).unwrap();
        let index_before = ctx.policy_bpf_state.index_state().unwrap();
        let idx_key = PolicyIndexKey {
            src_id: ANY_ID,
            dst_id: 31,
            direction: PolicyDirection::ingress_u8(),
            _pad: [0; 3],
        };
        let old_ruleset_id = *index_before
            .get(&idx_key)
            .expect("expected initial ingress entry");

        insert(&mut policy_writer, policy_v2);
        identity.reconcile(ctx.clone()).unwrap();
        let index_after = ctx.policy_bpf_state.index_state().unwrap();
        let new_ruleset_id = *index_after
            .get(&idx_key)
            .expect("expected updated ingress entry");
        assert_ne!(old_ruleset_id, new_ruleset_id);

        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();
        assert!(
            rules.keys().all(|key| key.ruleset_id != old_ruleset_id),
            "old ruleset entries should be removed"
        );
        assert!(
            rules.keys().any(|key| key.ruleset_id == new_ruleset_id),
            "new ruleset entries should exist"
        );
    }
}
