use std::{net::IpAddr, str::FromStr, sync::Arc};

use ahash::{HashMap, HashSet};
use ipnetwork::IpNetwork;
use k8s_openapi::{
    api::{
        core::v1::{ContainerPort, Pod},
        networking::v1::{IPBlock, NetworkPolicy, NetworkPolicyPeer, NetworkPolicyPort},
    },
    apimachinery::pkg::util::intstr::IntOrString,
};
use kube::{ResourceExt, runtime::controller::Action};
use mesh_cni_crds::v1alpha1::{
    cidridentity::CIDRIdentity,
    identity::Identity,
    meshidentityslice::{MeshIdentityNamedPort, MeshIdentitySlice},
};
use mesh_cni_ebpf_common::{
    IdentityId,
    policy::{
        ANY_ID, ANY_PORT, Action as PolicyAction, CidrPolicyMapKey, CidrPolicyMapKeyV4,
        CidrPolicyMapKeyV6, PolicyDirection, PolicyIndexKey, PolicyProtocol, PolicyRuleKey,
        PolicyValue, RULESET_NONE, RulesetId,
    },
};
use tracing::info;

use crate::{
    PolicyControllerBpf, Result,
    context::{Context, hash_rule_triples},
    controller::DEFAULT_REQUEUE_DURATION,
    selector::{
        PolicyType, peer_selects_identity, peer_selects_mesh_identity_slice, policy_affects_type,
        policy_selects_identity,
    },
};

pub(crate) async fn reconcile_policy_with_identity<P: PolicyControllerBpf>(
    identity: Arc<Identity>,
    ctx: Arc<Context<P>>,
) -> Result<Action> {
    inner_reconcile_policy_with_identity(identity, ctx)
}

// Policy enforcement is broken up into two seperate BPF maps. The first map is keyed on
// the src_id, dst_id, and policy direction returning a ruleset_id. This ruleset_id
// can be combined with protocol and destination port to determine the desired action and
// allowing wildcard checks on port and proto. This ideally cuts down the number of BPF map
// checks for a new flow as well as allowing for re-usable rulesets reducing map size.
// We compute per-peer ingress/egress rules, resolve named ports against the peer
// identity's pods (when used in the policy), then diff desired vs current index
// entries and update BPF maps while releasing unused rulesets.
pub fn inner_reconcile_policy_with_identity<P: PolicyControllerBpf>(
    identity: Arc<Identity>,
    ctx: Arc<Context<P>>,
) -> Result<Action> {
    let policy_state = ctx.policy_store.state();
    let selected_netpols: Vec<&Arc<NetworkPolicy>> = policy_state
        .iter()
        .filter(|np| policy_selects_identity(np, &identity))
        .collect();

    let identity_id = identity.spec.id;
    let identities = ctx.identity_store.state();
    let cidr_identities = ctx.cidr_identity_store.state();
    let mesh_identity_slices = ctx.mesh_identity_slice_store.state();
    let pods = ctx.pod_store.state();

    let mut generated_rules = generate_rules_maps(
        selected_netpols.as_slice(),
        &identity,
        &identities,
        &cidr_identities,
        &mesh_identity_slices,
        &pods,
    );

    let index_state = ctx.policy_bpf_state.index_state()?;
    let cidr_state = ctx.policy_bpf_state.cidr_index_state()?;
    let mut written_rulesets: HashSet<RulesetId> = HashSet::default();

    reconcile_identity_phase(
        ctx.as_ref(),
        identity_id,
        &selected_netpols,
        &index_state,
        &mut generated_rules,
        &mut written_rulesets,
    )?;
    reconcile_cidr_phase(
        ctx.as_ref(),
        identity_id,
        &selected_netpols,
        &cidr_state,
        &mut generated_rules,
        &mut written_rulesets,
    )?;

    Ok(Action::requeue(DEFAULT_REQUEUE_DURATION))
}

fn reconcile_identity_phase<P: PolicyControllerBpf>(
    ctx: &Context<P>,
    identity_id: IdentityId,
    selected_netpols: &[&Arc<NetworkPolicy>],
    index_state: &HashMap<PolicyIndexKey, RulesetId>,
    generated_rules: &mut GeneratedRules,
    written_rulesets: &mut HashSet<RulesetId>,
) -> Result<()> {
    let has_ingress_policy = selected_netpols.iter().any(|np| {
        let Some(spec) = &np.spec else {
            return false;
        };
        policy_affects_type(spec, PolicyType::Ingress)
    });
    let has_egress_policy = selected_netpols.iter().any(|np| {
        let Some(spec) = &np.spec else {
            return false;
        };
        policy_affects_type(spec, PolicyType::Egress)
    });

    let mut desired_index: HashMap<PolicyIndexKey, RulesetId> = HashMap::default();

    let mut ingress_identity_rules = std::mem::take(&mut generated_rules.ingress_identity_rules);
    if has_ingress_policy && !ingress_identity_rules.contains_key(&ANY_ID) {
        ingress_identity_rules.insert(ANY_ID, Vec::new());
    }
    for (peer_id, rule_specs) in ingress_identity_rules {
        let (ruleset_id, ruleset_entries) = build_ruleset(rule_specs.to_vec(), &ctx.ruleset_state);
        if written_rulesets.insert(ruleset_id) {
            for (key, value) in &ruleset_entries {
                ctx.policy_bpf_state.update_rule(*key, *value)?;
            }
        }
        desired_index.insert(
            PolicyIndexKey {
                src_id: peer_id,
                dst_id: identity_id,
                direction: PolicyDirection::Ingress.into(),
                _pad: [0; 3],
            },
            ruleset_id,
        );
    }

    let mut egress_identity_rules = std::mem::take(&mut generated_rules.egress_identity_rules);
    if has_egress_policy && !egress_identity_rules.contains_key(&ANY_ID) {
        egress_identity_rules.insert(ANY_ID, Vec::new());
    }
    for (peer_id, rule_specs) in egress_identity_rules {
        let (ruleset_id, ruleset_entries) = build_ruleset(rule_specs.to_vec(), &ctx.ruleset_state);
        if written_rulesets.insert(ruleset_id) {
            for (key, value) in &ruleset_entries {
                ctx.policy_bpf_state.update_rule(*key, *value)?;
            }
        }
        desired_index.insert(
            PolicyIndexKey {
                src_id: identity_id,
                dst_id: peer_id,
                direction: PolicyDirection::Egress.into(),
                _pad: [0; 3],
            },
            ruleset_id,
        );
    }

    let current_index: HashMap<PolicyIndexKey, RulesetId> = index_state
        .iter()
        .filter(|(key, _)| identity_key_applies(identity_id, key))
        .map(|(key, value)| (*key, *value))
        .collect();

    info!(
        identity_id,
        selected_policies = selected_netpols.len(),
        current_index = current_index.len(),
        desired_index = desired_index.len(),
        "reconcile: identity phase computed diff"
    );

    let mut deleted_count: u32 = 0;
    let mut updated_count: u32 = 0;
    let mut unchanged_count: u32 = 0;
    let mut added_count: u32 = 0;

    for (key, current_ruleset_id) in &current_index {
        match desired_index.get(key) {
            Some(desired_ruleset_id) if *desired_ruleset_id == *current_ruleset_id => {
                unchanged_count += 1;
            }
            Some(desired_ruleset_id) => {
                ctx.policy_bpf_state
                    .update_index(*key, *desired_ruleset_id)?;
                release_ruleset_if_unused(ctx, *current_ruleset_id)?;
                updated_count += 1;
            }
            None => {
                ctx.policy_bpf_state.delete_index(key)?;
                release_ruleset_if_unused(ctx, *current_ruleset_id)?;
                deleted_count += 1;
            }
        }
    }

    for (key, ruleset_id) in desired_index {
        if current_index.contains_key(&key) {
            continue;
        }
        ctx.policy_bpf_state.update_index(key, ruleset_id)?;
        added_count += 1;
    }

    info!(
        identity_id,
        deleted = deleted_count,
        updated = updated_count,
        unchanged = unchanged_count,
        added = added_count,
        "reconcile: identity phase applied diff"
    );
    Ok(())
}

fn reconcile_cidr_phase<P: PolicyControllerBpf>(
    ctx: &Context<P>,
    identity_id: IdentityId,
    selected_netpols: &[&Arc<NetworkPolicy>],
    cidr_state: &HashMap<CidrPolicyMapKey, RulesetId>,
    generated_rules: &mut GeneratedRules,
    written_rulesets: &mut HashSet<RulesetId>,
) -> Result<()> {
    let raw_cidr_rules = std::mem::take(&mut generated_rules.cidr_rules);

    let desired_cidr_rules = expand_cidr_rule_specs(&raw_cidr_rules);

    let mut desired_cidr: HashMap<CidrPolicyMapKey, RulesetId> = HashMap::default();

    for (key, rule_specs) in desired_cidr_rules {
        let (ruleset_id, ruleset_entries) = build_ruleset(rule_specs, &ctx.ruleset_state);
        if written_rulesets.insert(ruleset_id) {
            for (rule_key, rule_value) in &ruleset_entries {
                ctx.policy_bpf_state.update_rule(*rule_key, *rule_value)?;
            }
        }
        desired_cidr.insert(key, ruleset_id);
    }

    let current_cidr: HashMap<CidrPolicyMapKey, RulesetId> = cidr_state
        .iter()
        .filter(|(key, _)| cidr_key_applies(identity_id, key.selected_id()))
        .map(|(key, value)| (key.clone(), *value))
        .collect();

    info!(
        identity_id,
        selected_policies = selected_netpols.len(),
        current_cidr = current_cidr.len(),
        desired_cidr = desired_cidr.len(),
        "reconcile: cidr phase computed diff"
    );

    let mut cidr_deleted_count: u32 = 0;
    let mut cidr_updated_count: u32 = 0;
    let mut cidr_unchanged_count: u32 = 0;
    let mut cidr_added_count: u32 = 0;

    for (key, current_ruleset_id) in &current_cidr {
        match desired_cidr.get(key) {
            Some(desired_ruleset_id) if *desired_ruleset_id == *current_ruleset_id => {
                cidr_unchanged_count += 1;
            }
            Some(desired_ruleset_id) => {
                ctx.policy_bpf_state
                    .update_cidr_index(key.clone(), *desired_ruleset_id)?;
                release_ruleset_if_unused(ctx, *current_ruleset_id)?;
                cidr_updated_count += 1;
            }
            None => {
                ctx.policy_bpf_state.delete_cidr_index(key)?;
                release_ruleset_if_unused(ctx, *current_ruleset_id)?;
                cidr_deleted_count += 1;
            }
        }
    }

    for (key, ruleset_id) in desired_cidr {
        if current_cidr.contains_key(&key) {
            continue;
        }
        ctx.policy_bpf_state.update_cidr_index(key, ruleset_id)?;
        cidr_added_count += 1;
    }

    info!(
        identity_id,
        cidr_deleted = cidr_deleted_count,
        cidr_updated = cidr_updated_count,
        cidr_unchanged = cidr_unchanged_count,
        cidr_added = cidr_added_count,
        "reconcile: cidr phase applied diff"
    );
    Ok(())
}

#[derive(Default)]
struct GeneratedRules {
    ingress_identity_rules: HashMap<IdentityId, Vec<RuleSpec>>,
    egress_identity_rules: HashMap<IdentityId, Vec<RuleSpec>>,
    cidr_rules: HashMap<CidrPolicyMapKey, Vec<RuleSpec>>,
}

fn generate_rules_maps(
    selected_netpols: &[&Arc<NetworkPolicy>],
    identity: &Identity,
    identities: &[Arc<Identity>],
    cidr_identities: &[Arc<CIDRIdentity>],
    mesh_identity_slices: &[Arc<MeshIdentitySlice>],
    pods: &[Arc<Pod>],
) -> GeneratedRules {
    let identity_by_id: HashMap<u32, Arc<Identity>> = identities
        .iter()
        .map(|id| (id.spec.id, id.clone()))
        .collect();
    let mut generated_rules = GeneratedRules::default();

    for policy in selected_netpols {
        let Some(spec) = &policy.spec else {
            continue;
        };

        let Some(policy_ns) = policy.namespace() else {
            continue;
        };

        if policy_affects_type(spec, PolicyType::Ingress) {
            let rules = spec.ingress.as_deref().unwrap_or(&[]);
            for rule in rules {
                let rule_specs = rule_specs_from_ports(identity, pods, rule.ports.as_ref());
                let peer_ids = peer_ids_for_rule(&policy_ns, rule.from.as_ref(), identities);
                for peer_id in peer_ids {
                    let rule_specs = rule_specs_for_peer(
                        peer_id,
                        identity,
                        &identity_by_id,
                        pods,
                        rule.ports.as_ref(),
                    );
                    add_rule_specs(
                        &mut generated_rules.ingress_identity_rules,
                        &[peer_id],
                        &rule_specs,
                    );
                }

                if let Some(peers) = rule.from.as_ref() {
                    for peer in peers {
                        let Some(ip_block) = &peer.ip_block else {
                            continue;
                        };
                        add_cidr_rule_specs_for_ip_block(
                            ip_block,
                            cidr_identities,
                            identity.spec.id,
                            PolicyDirection::Ingress,
                            &rule_specs,
                            &mut generated_rules.cidr_rules,
                        );
                    }
                }
                let peer_endpoints =
                    peer_endpoints_for_rule(&policy_ns, rule.from.as_ref(), mesh_identity_slices);
                add_cidr_rule_specs_for_peer_endpoints(
                    &peer_endpoints,
                    identity.spec.id,
                    PolicyDirection::Ingress,
                    rule.ports.as_ref(),
                    &mut generated_rules.cidr_rules,
                );
            }
        }

        if policy_affects_type(spec, PolicyType::Egress) {
            let rules = spec.egress.as_deref().unwrap_or(&[]);
            for rule in rules {
                let rule_specs = rule_specs_from_ports(identity, pods, rule.ports.as_ref());
                let peer_ids = peer_ids_for_rule(&policy_ns, rule.to.as_ref(), identities);
                for peer_id in peer_ids {
                    let rule_specs = rule_specs_for_peer(
                        peer_id,
                        identity,
                        &identity_by_id,
                        pods,
                        rule.ports.as_ref(),
                    );
                    add_rule_specs(
                        &mut generated_rules.egress_identity_rules,
                        &[peer_id],
                        &rule_specs,
                    );
                }

                if let Some(peers) = rule.to.as_ref() {
                    for peer in peers {
                        let Some(ip_block) = &peer.ip_block else {
                            continue;
                        };
                        add_cidr_rule_specs_for_ip_block(
                            ip_block,
                            cidr_identities,
                            identity.spec.id,
                            PolicyDirection::Egress,
                            &rule_specs,
                            &mut generated_rules.cidr_rules,
                        );
                    }
                }
                let peer_endpoints =
                    peer_endpoints_for_rule(&policy_ns, rule.to.as_ref(), mesh_identity_slices);
                add_cidr_rule_specs_for_peer_endpoints(
                    &peer_endpoints,
                    identity.spec.id,
                    PolicyDirection::Egress,
                    rule.ports.as_ref(),
                    &mut generated_rules.cidr_rules,
                );
            }
        }
    }

    generated_rules
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
            proto: PolicyProtocol::Any.into(),
            port: ANY_PORT,
            action: PolicyAction::Allow.into(),
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
        let Some(proto) = parse_policy_proto(port.protocol.as_deref()) else {
            continue;
        };

        let Some(port_value) = &port.port else {
            specs.push(RuleSpec {
                proto,
                port: ANY_PORT,
                action: PolicyAction::Allow.into(),
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
                    action: PolicyAction::Allow.into(),
                });
            }
            IntOrString::String(port_name) => {
                let resolved_ports = resolve_named_ports(identity, pods, port_name, proto);
                for resolved_port in resolved_ports {
                    specs.push(RuleSpec {
                        proto,
                        port: resolved_port,
                        action: PolicyAction::Allow.into(),
                    });
                }
            }
        }
    }

    specs
}

fn rule_specs_from_mesh_endpoint_ports(
    endpoint: &MeshPeerEndpoint,
    ports: Option<&Vec<NetworkPolicyPort>>,
) -> Vec<RuleSpec> {
    let ports = match ports {
        None => return vec![RuleSpec::default()],
        Some(p) if p.is_empty() => return vec![RuleSpec::default()],
        Some(p) => p,
    };

    let mut specs = Vec::new();
    for port in ports {
        let Some(proto) = parse_policy_proto(port.protocol.as_deref()) else {
            continue;
        };

        let Some(port_value) = &port.port else {
            specs.push(RuleSpec {
                proto,
                port: ANY_PORT,
                action: PolicyAction::Allow.into(),
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
                    action: PolicyAction::Allow.into(),
                });
            }
            IntOrString::String(port_name) => {
                for named_port in &endpoint.named_ports {
                    if named_port.name != *port_name {
                        continue;
                    }
                    if !mesh_named_port_matches_protocol(named_port, proto) {
                        continue;
                    }
                    specs.push(RuleSpec {
                        proto,
                        port: named_port.port,
                        action: PolicyAction::Allow.into(),
                    });
                }
            }
        }
    }

    specs
}

fn rule_specs_for_peer(
    peer_id: IdentityId,
    self_identity: &Identity,
    identities: &HashMap<IdentityId, Arc<Identity>>,
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
    let Some(declared) = parse_policy_proto(container_port.protocol.as_deref()) else {
        return false;
    };

    proto == declared
}

fn mesh_named_port_matches_protocol(named_port: &MeshIdentityNamedPort, proto: u8) -> bool {
    let Some(declared) = parse_policy_proto(Some(named_port.protocol.as_str())) else {
        return false;
    };
    proto == declared
}

fn parse_policy_proto(proto: Option<&str>) -> Option<u8> {
    match proto {
        None => Some(PolicyProtocol::Tcp.into()),
        Some("TCP") => Some(PolicyProtocol::Tcp.into()),
        Some("UDP") => Some(PolicyProtocol::Udp.into()),
        Some("SCTP") => Some(PolicyProtocol::Sctp.into()),
        Some(_) => None,
    }
}

fn peer_ids_for_rule(
    policy_ns: &str,
    peers: Option<&Vec<NetworkPolicyPeer>>,
    identities: &[Arc<Identity>],
) -> Vec<IdentityId> {
    let Some(peers) = peers else {
        return vec![ANY_ID];
    };
    if peers.is_empty() {
        return vec![ANY_ID];
    }

    let mut ids = Vec::new();
    for peer in peers {
        if peer.ip_block.is_some() {
            continue;
        }

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

#[derive(Clone, Debug)]
struct MeshPeerEndpoint {
    ip: IpAddr,
    named_ports: Vec<MeshIdentityNamedPort>,
}

fn peer_endpoints_for_rule(
    policy_ns: &str,
    peers: Option<&Vec<NetworkPolicyPeer>>,
    mesh_identity_slices: &[Arc<MeshIdentitySlice>],
) -> Vec<MeshPeerEndpoint> {
    let Some(peers) = peers else {
        return Vec::new();
    };
    if peers.is_empty() {
        return Vec::new();
    }

    let mut endpoints: HashMap<IpAddr, Vec<MeshIdentityNamedPort>> = HashMap::default();
    for peer in peers {
        if peer.ip_block.is_some() {
            continue;
        }
        let same_namespace_only = peer.namespace_selector.is_none() && peer.pod_selector.is_some();
        for slice in mesh_identity_slices {
            let Some(slice_ns) = slice.namespace() else {
                continue;
            };
            if same_namespace_only && slice_ns.as_str() != policy_ns {
                continue;
            }
            if !peer_selects_mesh_identity_slice(peer, slice.as_ref()) {
                continue;
            }
            for endpoint in &slice.spec.endpoints {
                let named_ports = endpoints.entry(endpoint.ip).or_default();
                for named_port in &endpoint.named_ports {
                    if !named_ports.iter().any(|existing| existing == named_port) {
                        named_ports.push(named_port.clone());
                    }
                }
            }
        }
    }

    endpoints
        .into_iter()
        .map(|(ip, named_ports)| MeshPeerEndpoint { ip, named_ports })
        .collect()
}

fn cidr_prefixes_for_ip_block(
    ip_block: &IPBlock,
    cidr_identities: &[Arc<CIDRIdentity>],
) -> Vec<IpNetwork> {
    let mut except = ip_block.except.clone().unwrap_or_default();
    except.sort();
    except.dedup();

    let mut prefixes: HashSet<IpNetwork> = HashSet::default();
    cidr_identities
        .iter()
        .filter(|cidr_identity| {
            if cidr_identity.spec.cidr.as_deref() != Some(ip_block.cidr.as_str()) {
                return false;
            }

            let mut cidr_except = cidr_identity.spec.except.clone();
            cidr_except.sort();
            cidr_except.dedup();
            cidr_except == except
        })
        .for_each(|cidr_identity| {
            for prefix in &cidr_identity.spec.cidr_prefixes {
                if let Ok(parsed) = IpNetwork::from_str(prefix) {
                    prefixes.insert(parsed);
                }
            }
        });

    prefixes.into_iter().collect()
}

fn add_cidr_rule_specs_for_ip_block(
    ip_block: &IPBlock,
    cidr_identities: &[Arc<CIDRIdentity>],
    selected_id: IdentityId,
    direction: PolicyDirection,
    rule_specs: &[RuleSpec],
    cidr_map: &mut HashMap<CidrPolicyMapKey, Vec<RuleSpec>>,
) {
    for prefix in cidr_prefixes_for_ip_block(ip_block, cidr_identities) {
        match prefix {
            IpNetwork::V4(prefix_v4) => {
                let key = CidrPolicyMapKey::V4(CidrPolicyMapKeyV4 {
                    prefix_len: 64 + u32::from(prefix_v4.prefix()),
                    selected_id,
                    direction: direction.into(),
                    _pad: [0; 3],
                    addr: prefix_v4.network().octets(),
                });
                cidr_map
                    .entry(key)
                    .or_default()
                    .extend_from_slice(rule_specs);
            }
            IpNetwork::V6(prefix_v6) => {
                let key = CidrPolicyMapKey::V6(CidrPolicyMapKeyV6 {
                    prefix_len: 64 + u32::from(prefix_v6.prefix()),
                    selected_id,
                    direction: direction.into(),
                    _pad: [0; 3],
                    addr: u128::from(prefix_v6.network()).to_be_bytes(),
                });
                cidr_map
                    .entry(key)
                    .or_default()
                    .extend_from_slice(rule_specs);
            }
        }
    }
}

fn add_cidr_rule_specs_for_peer_ips(
    peer_ips: &[IpAddr],
    selected_id: IdentityId,
    direction: PolicyDirection,
    rule_specs: &[RuleSpec],
    cidr_map: &mut HashMap<CidrPolicyMapKey, Vec<RuleSpec>>,
) {
    for ip in peer_ips {
        match ip {
            IpAddr::V4(ipv4) => {
                let key = CidrPolicyMapKey::V4(CidrPolicyMapKeyV4 {
                    prefix_len: 64 + 32,
                    selected_id,
                    direction: direction.into(),
                    _pad: [0; 3],
                    addr: ipv4.octets(),
                });
                cidr_map
                    .entry(key)
                    .or_default()
                    .extend_from_slice(rule_specs);
            }
            IpAddr::V6(ipv6) => {
                let key = CidrPolicyMapKey::V6(CidrPolicyMapKeyV6 {
                    prefix_len: 64 + 128,
                    selected_id,
                    direction: direction.into(),
                    _pad: [0; 3],
                    addr: ipv6.to_bits().to_be_bytes(),
                });
                cidr_map
                    .entry(key)
                    .or_default()
                    .extend_from_slice(rule_specs);
            }
        }
    }
}

fn add_cidr_rule_specs_for_peer_endpoints(
    peer_endpoints: &[MeshPeerEndpoint],
    selected_id: IdentityId,
    direction: PolicyDirection,
    ports: Option<&Vec<NetworkPolicyPort>>,
    cidr_map: &mut HashMap<CidrPolicyMapKey, Vec<RuleSpec>>,
) {
    for endpoint in peer_endpoints {
        let rule_specs = rule_specs_from_mesh_endpoint_ports(endpoint, ports);
        add_cidr_rule_specs_for_peer_ips(
            &[endpoint.ip],
            selected_id,
            direction,
            &rule_specs,
            cidr_map,
        );
    }
}

fn expand_cidr_rule_specs(
    source_rules: &HashMap<CidrPolicyMapKey, Vec<RuleSpec>>,
) -> HashMap<CidrPolicyMapKey, Vec<RuleSpec>> {
    let mut expanded_rules: HashMap<CidrPolicyMapKey, Vec<RuleSpec>> = HashMap::default();

    for key in source_rules.keys() {
        let mut effective_rules = Vec::new();
        for (ancestor_key, ancestor_rules) in source_rules {
            if cidr_key_contains(ancestor_key, key) {
                effective_rules.extend_from_slice(ancestor_rules);
            }
        }
        expanded_rules.insert(key.clone(), effective_rules);
    }

    expanded_rules
}

fn cidr_key_contains(ancestor_key: &CidrPolicyMapKey, descendant_key: &CidrPolicyMapKey) -> bool {
    match (ancestor_key, descendant_key) {
        (CidrPolicyMapKey::V4(ancestor), CidrPolicyMapKey::V4(descendant)) => {
            if ancestor.selected_id != descendant.selected_id
                || ancestor.direction != descendant.direction
                || ancestor.prefix_len > descendant.prefix_len
            {
                return false;
            }
            let Some(prefix_bits) = ancestor.prefix_len.checked_sub(64) else {
                return false;
            };
            if prefix_bits > 32 {
                return false;
            }
            prefix_matches(&ancestor.addr, &descendant.addr, prefix_bits)
        }
        (CidrPolicyMapKey::V6(ancestor), CidrPolicyMapKey::V6(descendant)) => {
            if ancestor.selected_id != descendant.selected_id
                || ancestor.direction != descendant.direction
                || ancestor.prefix_len > descendant.prefix_len
            {
                return false;
            }
            let Some(prefix_bits) = ancestor.prefix_len.checked_sub(64) else {
                return false;
            };
            if prefix_bits > 128 {
                return false;
            }
            prefix_matches(&ancestor.addr, &descendant.addr, prefix_bits)
        }
        _ => false,
    }
}

fn prefix_matches(prefix_addr: &[u8], candidate_addr: &[u8], prefix_bits: u32) -> bool {
    let full_bytes = (prefix_bits / 8) as usize;
    let partial_bits = (prefix_bits % 8) as u8;

    if full_bytes > prefix_addr.len() || full_bytes > candidate_addr.len() {
        return false;
    }

    if prefix_addr[..full_bytes] != candidate_addr[..full_bytes] {
        return false;
    }

    if partial_bits == 0 {
        return true;
    }

    if full_bytes >= prefix_addr.len() || full_bytes >= candidate_addr.len() {
        return false;
    }

    let mask = (!0u8) << (8 - partial_bits);
    (prefix_addr[full_bytes] & mask) == (candidate_addr[full_bytes] & mask)
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

    let hash = hash_rule_triples(
        rules
            .iter()
            .map(|rule| (rule.proto, rule.port, rule.action)),
    );

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

fn cidr_key_applies(identity_id: IdentityId, selected_id: IdentityId) -> bool {
    selected_id == identity_id
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
            core::v1::{Container, ContainerPort, Pod, PodIP, PodSpec, PodStatus},
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
    use mesh_cni_crds::v1alpha1::{
        cidridentity::{CIDRIdentity, CidrIdentitySpec},
        identity::IdentitySpec,
        meshidentityslice::{
            MeshIdentityEndpoint, MeshIdentityNamedPort, MeshIdentitySlice, MeshIdentitySliceSpec,
        },
    };

    use super::*;
    use crate::{
        Result,
        context::{Context, RulesetState},
    };

    struct TestPolicyBpfState {
        index: Mutex<HashMap<PolicyIndexKey, RulesetId>>,
        ruleset: Mutex<HashMap<PolicyRuleKey, PolicyValue>>,
        cidr_v4: Mutex<HashMap<CidrPolicyMapKeyV4, RulesetId>>,
        cidr_v6: Mutex<HashMap<CidrPolicyMapKeyV6, RulesetId>>,
    }

    impl TestPolicyBpfState {
        fn new() -> Self {
            Self {
                index: Mutex::new(HashMap::default()),
                ruleset: Mutex::new(HashMap::default()),
                cidr_v4: Mutex::new(HashMap::default()),
                cidr_v6: Mutex::new(HashMap::default()),
            }
        }
    }

    impl PolicyControllerBpf for TestPolicyBpfState {
        fn update_index(&self, key: PolicyIndexKey, ruleset_id: RulesetId) -> Result<()> {
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

        fn index_state(&self) -> Result<HashMap<PolicyIndexKey, RulesetId>> {
            Ok(self.index.lock().unwrap().clone())
        }

        fn ruleset_state(&self) -> Result<HashMap<PolicyRuleKey, PolicyValue>> {
            Ok(self.ruleset.lock().unwrap().clone())
        }

        fn update_cidr_index(&self, key: CidrPolicyMapKey, ruleset_id: RulesetId) -> Result<()> {
            match key {
                CidrPolicyMapKey::V4(key) => {
                    self.cidr_v4.lock().unwrap().insert(key, ruleset_id);
                }
                CidrPolicyMapKey::V6(key) => {
                    self.cidr_v6.lock().unwrap().insert(key, ruleset_id);
                }
            }
            Ok(())
        }

        fn delete_cidr_index(&self, key: &CidrPolicyMapKey) -> Result<()> {
            match key {
                CidrPolicyMapKey::V4(key) => {
                    self.cidr_v4.lock().unwrap().remove(key);
                }
                CidrPolicyMapKey::V6(key) => {
                    self.cidr_v6.lock().unwrap().remove(key);
                }
            }
            Ok(())
        }

        fn cidr_index_state(&self) -> Result<HashMap<CidrPolicyMapKey, RulesetId>> {
            let mut state = HashMap::default();
            for (key, value) in self.cidr_v4.lock().unwrap().iter() {
                state.insert(CidrPolicyMapKey::V4(*key), *value);
            }
            for (key, value) in self.cidr_v6.lock().unwrap().iter() {
                state.insert(CidrPolicyMapKey::V6(*key), *value);
            }
            Ok(state)
        }
    }

    fn insert<K: Clone + Lookup + 'static>(writer: &mut Writer<K>, obj: K)
    where
        K::DynamicType: Eq + Hash + Clone,
    {
        writer.apply_watcher_event(&watcher::Event::Apply(obj));
    }

    fn pod_with_ip(namespace: &str, name: &str, labels: BTreeMap<String, String>, ip: &str) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some(namespace.into()),
                labels: Some(labels),
                ..Default::default()
            },
            status: Some(PodStatus {
                pod_ips: Some(vec![PodIP { ip: ip.into() }]),
                ..Default::default()
            }),
            ..Default::default()
        }
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
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

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
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let idx_key = PolicyIndexKey {
            src_id: ANY_ID,
            dst_id: 10,
            direction: PolicyDirection::Ingress.into(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&idx_key).expect("expected index entry");
        assert_ne!(ruleset_id, RULESET_NONE);

        let rule_key_a = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::Tcp.into(),
            _pad0: [0; 3],
            port: 8080,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key_a).expect("expected ruleset entry");
        assert_eq!(rule.action, PolicyAction::Allow as u8);

        let rule_key_b = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::Tcp.into(),
            _pad0: [0; 3],
            port: 8081,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key_b).expect("expected ruleset entry");
        assert_eq!(rule.action, PolicyAction::Allow as u8);
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
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

        insert(&mut identity_writer, identity.clone());

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let idx_key = PolicyIndexKey {
            src_id: 42,
            dst_id: ANY_ID,
            direction: PolicyDirection::Any.into(),
            _pad: [0; 3],
        };
        assert!(!index.contains_key(&idx_key));
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
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

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
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();
        let idx_key = PolicyIndexKey {
            src_id: ANY_ID,
            dst_id: 7,
            direction: PolicyDirection::Ingress.into(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&idx_key).expect("expected any-id ingress entry");
        assert_ne!(ruleset_id, RULESET_NONE);
        let rule_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::Tcp.into(),
            _pad0: [0; 3],
            port: 80,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key).expect("expected ruleset entry");
        assert_eq!(rule.action, PolicyAction::Allow as u8);
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
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

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
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let idx_key = PolicyIndexKey {
            src_id: ANY_ID,
            dst_id: 9,
            direction: PolicyDirection::Ingress.into(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&idx_key).expect("expected ingress deny entry");
        assert_ne!(ruleset_id, RULESET_NONE);

        assert!(
            rules.keys().all(|key| key.ruleset_id != ruleset_id),
            "expected no allow rules for deny-by-default"
        );
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
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

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
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let idx_key = PolicyIndexKey {
            src_id: 11,
            dst_id: ANY_ID,
            direction: PolicyDirection::Egress.into(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&idx_key).expect("expected any-id egress entry");
        assert_ne!(ruleset_id, RULESET_NONE);

        let rule_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::Tcp.into(),
            _pad0: [0; 3],
            port: 443,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key).expect("expected ruleset entry");
        assert_eq!(rule.action, PolicyAction::Allow as u8);
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
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

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
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let idx_key = PolicyIndexKey {
            src_id: 12,
            dst_id: ANY_ID,
            direction: PolicyDirection::Egress.into(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&idx_key).expect("expected egress deny entry");
        assert_ne!(ruleset_id, RULESET_NONE);

        assert!(
            rules.keys().all(|key| key.ruleset_id != ruleset_id),
            "expected no allow rules for deny-by-default"
        );
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
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

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
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();

        let ingress_key = PolicyIndexKey {
            src_id: ANY_ID,
            dst_id: 13,
            direction: PolicyDirection::Ingress.into(),
            _pad: [0; 3],
        };
        assert!(!index.contains_key(&ingress_key));
    }

    #[test]
    fn reconcile_named_port_mismatch_denies_by_default() {
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
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

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
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let idx_key = PolicyIndexKey {
            src_id: ANY_ID,
            dst_id: 14,
            direction: PolicyDirection::Ingress.into(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&idx_key).expect("expected ingress entry");
        assert_ne!(ruleset_id, RULESET_NONE);

        assert!(
            rules.keys().all(|key| key.ruleset_id != ruleset_id),
            "expected no allow rules for deny-by-default"
        );
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
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

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
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let allowed_key = PolicyIndexKey {
            src_id: 22,
            dst_id: 21,
            direction: PolicyDirection::Ingress.into(),
            _pad: [0; 3],
        };
        let denied_key = PolicyIndexKey {
            src_id: 23,
            dst_id: 21,
            direction: PolicyDirection::Ingress.into(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&allowed_key).expect("expected allowed peer");
        assert!(!index.contains_key(&denied_key));

        let rule_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::Tcp.into(),
            _pad0: [0; 3],
            port: 80,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key).expect("expected allow rule");
        assert_eq!(rule.action, PolicyAction::Allow as u8);
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
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

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
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let idx_key = PolicyIndexKey {
            src_id: 42,
            dst_id: 41,
            direction: PolicyDirection::Ingress.into(),
            _pad: [0; 3],
        };
        let ruleset_id = *index.get(&idx_key).expect("expected peer ingress entry");
        assert_ne!(ruleset_id, RULESET_NONE);

        let rule_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::Tcp.into(),
            _pad0: [0; 3],
            port: 8080,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key).expect("expected resolved named port");
        assert_eq!(rule.action, PolicyAction::Allow as u8);

        let deny_key = PolicyIndexKey {
            src_id: ANY_ID,
            dst_id: 41,
            direction: PolicyDirection::Ingress.into(),
            _pad: [0; 3],
        };
        let deny_ruleset_id = *index
            .get(&deny_key)
            .expect("expected any-id ingress deny entry");
        assert_ne!(deny_ruleset_id, RULESET_NONE);
        assert!(
            rules.keys().all(|key| key.ruleset_id != deny_ruleset_id),
            "deny ruleset should have no rules"
        );
    }

    #[test]
    fn reconcile_ingress_ipblock_uses_cidr_policy_map() {
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
                    labels.insert("pod".into(), "a".into());
                    labels
                },
                id: 501,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("x".into());

        let cidr_identity = CIDRIdentity::new(
            "cidr-10-244-0-0-24",
            CidrIdentitySpec {
                id: 777,
                cidr_prefixes: vec!["10.244.0.0/24".into()],
                cidr: Some("10.244.0.0/24".into()),
                except: vec![],
            },
        );

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-ipblock-ingress".into()),
                namespace: Some("x".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("pod".into(), "a".into());
                        labels
                    }),
                    ..Default::default()
                }),
                ingress: Some(vec![NetworkPolicyIngressRule {
                    from: Some(vec![NetworkPolicyPeer {
                        ip_block: Some(k8s_openapi::api::networking::v1::IPBlock {
                            cidr: "10.244.0.0/24".into(),
                            except: None,
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
        let (cidr_identity_store, mut cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, identity.clone());
        insert(&mut cidr_identity_writer, cidr_identity);

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let cidr = ctx.policy_bpf_state.cidr_index_state().unwrap();
        let allow_key = CidrPolicyMapKeyV4 {
            prefix_len: 64 + 24,
            selected_id: 501,
            direction: PolicyDirection::Ingress.into(),
            _pad: [0; 3],
            addr: std::net::Ipv4Addr::from_str("10.244.0.0")
                .expect("valid ipv4")
                .octets(),
        };
        assert!(cidr.contains_key(&CidrPolicyMapKey::V4(allow_key)));
    }

    #[test]
    fn reconcile_egress_ipblock_uses_cidr_policy_map() {
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
                    labels.insert("pod".into(), "a".into());
                    labels
                },
                id: 601,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("x".into());

        let cidr_identity = CIDRIdentity::new(
            "cidr-10-244-0-0-24-e",
            CidrIdentitySpec {
                id: 888,
                cidr_prefixes: vec!["10.244.0.0/24".into()],
                cidr: Some("10.244.0.0/24".into()),
                except: vec![],
            },
        );

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-ipblock-egress".into()),
                namespace: Some("x".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("pod".into(), "a".into());
                        labels
                    }),
                    ..Default::default()
                }),
                egress: Some(vec![NetworkPolicyEgressRule {
                    to: Some(vec![NetworkPolicyPeer {
                        ip_block: Some(k8s_openapi::api::networking::v1::IPBlock {
                            cidr: "10.244.0.0/24".into(),
                            except: None,
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
        let (cidr_identity_store, mut cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, identity.clone());
        insert(&mut cidr_identity_writer, cidr_identity);

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let cidr = ctx.policy_bpf_state.cidr_index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();
        let allow_key = CidrPolicyMapKeyV4 {
            prefix_len: 64 + 24,
            selected_id: 601,
            direction: PolicyDirection::Egress.into(),
            _pad: [0; 3],
            addr: std::net::Ipv4Addr::from_str("10.244.0.0")
                .expect("valid ipv4")
                .octets(),
        };
        assert!(cidr.contains_key(&CidrPolicyMapKey::V4(allow_key)));
        let ruleset_id = cidr.get(&CidrPolicyMapKey::V4(allow_key)).copied().unwrap();
        let rule_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::Tcp.into(),
            _pad0: [0; 3],
            port: 80,
            _pad1: [0; 2],
        };
        let rule = rules.get(&rule_key).expect("expected CIDR peer allow rule");
        assert_eq!(rule.action, PolicyAction::Allow as u8);
    }

    #[test]
    fn reconcile_egress_peer_selectors_include_mesh_identity_slice_ips() {
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
                    labels.insert("pod".into(), "a".into());
                    labels
                },
                id: 7771,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("x".into());

        let remote_slice = MeshIdentitySlice::new(
            "remote-a",
            MeshIdentitySliceSpec {
                cluster: "cluster2".into(),
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "remote".into());
                    labels
                },
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("team".into(), "blue".into());
                    labels
                },
                endpoints: vec![MeshIdentityEndpoint {
                    ip: "10.242.0.5".parse().expect("valid ip"),
                    named_ports: vec![],
                }],
            },
        );
        let mut remote_slice = remote_slice;
        remote_slice.metadata.namespace = Some("remote-ns".into());

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-remote-egress".into()),
                namespace: Some("x".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("pod".into(), "a".into());
                        labels
                    }),
                    ..Default::default()
                }),
                egress: Some(vec![NetworkPolicyEgressRule {
                    to: Some(vec![NetworkPolicyPeer {
                        namespace_selector: Some(LabelSelector {
                            match_labels: Some({
                                let mut labels = BTreeMap::new();
                                labels.insert("team".into(), "blue".into());
                                labels
                            }),
                            ..Default::default()
                        }),
                        pod_selector: Some(LabelSelector {
                            match_labels: Some({
                                let mut labels = BTreeMap::new();
                                labels.insert("app".into(), "remote".into());
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
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, mut mesh_identity_slice_writer) =
            store::<MeshIdentitySlice>();

        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, identity.clone());
        insert(&mut mesh_identity_slice_writer, remote_slice);

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let cidr = ctx.policy_bpf_state.cidr_index_state().unwrap();
        let key = CidrPolicyMapKey::V4(CidrPolicyMapKeyV4 {
            prefix_len: 64 + 32,
            selected_id: 7771,
            direction: PolicyDirection::Egress.into(),
            _pad: [0; 3],
            addr: std::net::Ipv4Addr::new(10, 242, 0, 5).octets(),
        });
        assert!(
            cidr.contains_key(&key),
            "expected mesh identity slice ip to be programmed as egress cidr peer"
        );
    }

    #[test]
    fn reconcile_egress_named_port_uses_mesh_identity_slice_endpoint_ports() {
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
                    labels.insert("pod".into(), "a".into());
                    labels
                },
                id: 7772,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("x".into());

        // Local selected pod has "http" on 8080, which must not be used for egress mesh peers.
        let local_pod = Pod {
            metadata: ObjectMeta {
                name: Some("a".into()),
                namespace: Some("x".into()),
                labels: Some({
                    let mut labels = BTreeMap::new();
                    labels.insert("pod".into(), "a".into());
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

        let remote_slice = MeshIdentitySlice::new(
            "remote-a",
            MeshIdentitySliceSpec {
                cluster: "cluster2".into(),
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "remote".into());
                    labels
                },
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("team".into(), "blue".into());
                    labels
                },
                endpoints: vec![MeshIdentityEndpoint {
                    ip: "10.242.0.5".parse().expect("valid ip"),
                    named_ports: vec![MeshIdentityNamedPort {
                        name: "http".into(),
                        protocol: "TCP".into(),
                        port: 9090,
                    }],
                }],
            },
        );
        let mut remote_slice = remote_slice;
        remote_slice.metadata.namespace = Some("remote-ns".into());

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-remote-egress".into()),
                namespace: Some("x".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("pod".into(), "a".into());
                        labels
                    }),
                    ..Default::default()
                }),
                egress: Some(vec![NetworkPolicyEgressRule {
                    to: Some(vec![NetworkPolicyPeer {
                        namespace_selector: Some(LabelSelector {
                            match_labels: Some({
                                let mut labels = BTreeMap::new();
                                labels.insert("team".into(), "blue".into());
                                labels
                            }),
                            ..Default::default()
                        }),
                        pod_selector: Some(LabelSelector {
                            match_labels: Some({
                                let mut labels = BTreeMap::new();
                                labels.insert("app".into(), "remote".into());
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
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, mut mesh_identity_slice_writer) =
            store::<MeshIdentitySlice>();

        insert(&mut pod_writer, local_pod);
        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, identity.clone());
        insert(&mut mesh_identity_slice_writer, remote_slice);

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let cidr = ctx.policy_bpf_state.cidr_index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();
        let key = CidrPolicyMapKey::V4(CidrPolicyMapKeyV4 {
            prefix_len: 64 + 32,
            selected_id: 7772,
            direction: PolicyDirection::Egress.into(),
            _pad: [0; 3],
            addr: std::net::Ipv4Addr::new(10, 242, 0, 5).octets(),
        });

        let ruleset_id = *cidr
            .get(&key)
            .expect("expected mesh identity slice ip to be programmed");
        let allow_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::Tcp.into(),
            _pad0: [0; 3],
            port: 9090,
            _pad1: [0; 2],
        };
        assert!(
            rules.contains_key(&allow_key),
            "expected named port to resolve from mesh endpoint metadata"
        );

        let wrong_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::Tcp.into(),
            _pad0: [0; 3],
            port: 8080,
            _pad1: [0; 2],
        };
        assert!(
            !rules.contains_key(&wrong_key),
            "expected local selected identity named port not to be used"
        );
    }

    #[test]
    fn reconcile_ingress_named_port_uses_mesh_identity_slice_endpoint_ports() {
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
                    labels.insert("pod".into(), "a".into());
                    labels
                },
                id: 7773,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("x".into());

        // Local selected pod has "http" on 8080, which must not be used for ingress mesh peers.
        let local_pod = Pod {
            metadata: ObjectMeta {
                name: Some("a".into()),
                namespace: Some("x".into()),
                labels: Some({
                    let mut labels = BTreeMap::new();
                    labels.insert("pod".into(), "a".into());
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

        let remote_slice = MeshIdentitySlice::new(
            "remote-a",
            MeshIdentitySliceSpec {
                cluster: "cluster2".into(),
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("app".into(), "remote".into());
                    labels
                },
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("team".into(), "blue".into());
                    labels
                },
                endpoints: vec![MeshIdentityEndpoint {
                    ip: "10.242.0.5".parse().expect("valid ip"),
                    named_ports: vec![MeshIdentityNamedPort {
                        name: "http".into(),
                        protocol: "TCP".into(),
                        port: 9090,
                    }],
                }],
            },
        );
        let mut remote_slice = remote_slice;
        remote_slice.metadata.namespace = Some("remote-ns".into());

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-remote-ingress".into()),
                namespace: Some("x".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("pod".into(), "a".into());
                        labels
                    }),
                    ..Default::default()
                }),
                ingress: Some(vec![NetworkPolicyIngressRule {
                    from: Some(vec![NetworkPolicyPeer {
                        namespace_selector: Some(LabelSelector {
                            match_labels: Some({
                                let mut labels = BTreeMap::new();
                                labels.insert("team".into(), "blue".into());
                                labels
                            }),
                            ..Default::default()
                        }),
                        pod_selector: Some(LabelSelector {
                            match_labels: Some({
                                let mut labels = BTreeMap::new();
                                labels.insert("app".into(), "remote".into());
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
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, mut mesh_identity_slice_writer) =
            store::<MeshIdentitySlice>();

        insert(&mut pod_writer, local_pod);
        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, identity.clone());
        insert(&mut mesh_identity_slice_writer, remote_slice);

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let cidr = ctx.policy_bpf_state.cidr_index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();
        let key = CidrPolicyMapKey::V4(CidrPolicyMapKeyV4 {
            prefix_len: 64 + 32,
            selected_id: 7773,
            direction: PolicyDirection::Ingress.into(),
            _pad: [0; 3],
            addr: std::net::Ipv4Addr::new(10, 242, 0, 5).octets(),
        });

        let ruleset_id = *cidr
            .get(&key)
            .expect("expected mesh identity slice ip to be programmed");
        let allow_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::Tcp.into(),
            _pad0: [0; 3],
            port: 9090,
            _pad1: [0; 2],
        };
        assert!(
            rules.contains_key(&allow_key),
            "expected named port to resolve from mesh endpoint metadata"
        );

        let wrong_key = PolicyRuleKey {
            ruleset_id,
            proto: PolicyProtocol::Tcp.into(),
            _pad0: [0; 3],
            port: 8080,
            _pad1: [0; 2],
        };
        assert!(
            !rules.contains_key(&wrong_key),
            "expected local selected identity named port not to be used"
        );
    }

    #[test]
    fn reconcile_ingress_ipblock_overlapping_prefixes_are_additive() {
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
                    labels.insert("pod".into(), "a".into());
                    labels
                },
                id: 911,
            },
        );
        let mut identity = identity;
        identity.metadata.namespace = Some("x".into());

        let broad_cidr_identity = CIDRIdentity::new(
            "cidr-10-0-0-0-8",
            CidrIdentitySpec {
                id: 9011,
                cidr_prefixes: vec!["10.0.0.0/8".into()],
                cidr: Some("10.0.0.0/8".into()),
                except: vec![],
            },
        );
        let narrow_cidr_identity = CIDRIdentity::new(
            "cidr-10-1-0-0-16",
            CidrIdentitySpec {
                id: 9012,
                cidr_prefixes: vec!["10.1.0.0/16".into()],
                cidr: Some("10.1.0.0/16".into()),
                except: vec![],
            },
        );

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-overlapping-ipblocks".into()),
                namespace: Some("x".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("pod".into(), "a".into());
                        labels
                    }),
                    ..Default::default()
                }),
                ingress: Some(vec![
                    NetworkPolicyIngressRule {
                        from: Some(vec![NetworkPolicyPeer {
                            ip_block: Some(k8s_openapi::api::networking::v1::IPBlock {
                                cidr: "10.0.0.0/8".into(),
                                except: None,
                            }),
                            ..Default::default()
                        }]),
                        ports: Some(vec![NetworkPolicyPort {
                            protocol: Some("TCP".into()),
                            port: Some(IntOrString::Int(80)),
                            ..Default::default()
                        }]),
                    },
                    NetworkPolicyIngressRule {
                        from: Some(vec![NetworkPolicyPeer {
                            ip_block: Some(k8s_openapi::api::networking::v1::IPBlock {
                                cidr: "10.1.0.0/16".into(),
                                except: None,
                            }),
                            ..Default::default()
                        }]),
                        ports: Some(vec![NetworkPolicyPort {
                            protocol: Some("TCP".into()),
                            port: Some(IntOrString::Int(443)),
                            ..Default::default()
                        }]),
                    },
                ]),
                ..Default::default()
            }),
        };

        let (pod_store, _pod_writer) = store::<Pod>();
        let (policy_store, mut policy_writer) = store::<NetworkPolicy>();
        let (identity_store, mut identity_writer) = store::<Identity>();
        let (cidr_identity_store, mut cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, identity.clone());
        insert(&mut cidr_identity_writer, broad_cidr_identity);
        insert(&mut cidr_identity_writer, narrow_cidr_identity);

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity, ctx.clone()).unwrap();

        let cidr = ctx.policy_bpf_state.cidr_index_state().unwrap();
        let rules = ctx.policy_bpf_state.ruleset_state().unwrap();

        let broad_key = CidrPolicyMapKeyV4 {
            prefix_len: 64 + 8,
            selected_id: 911,
            direction: PolicyDirection::Ingress.into(),
            _pad: [0; 3],
            addr: std::net::Ipv4Addr::from_str("10.0.0.0")
                .expect("valid ipv4")
                .octets(),
        };
        let narrow_key = CidrPolicyMapKeyV4 {
            prefix_len: 64 + 16,
            selected_id: 911,
            direction: PolicyDirection::Ingress.into(),
            _pad: [0; 3],
            addr: std::net::Ipv4Addr::from_str("10.1.0.0")
                .expect("valid ipv4")
                .octets(),
        };

        let broad_ruleset_id = *cidr
            .get(&CidrPolicyMapKey::V4(broad_key))
            .expect("expected broad key");
        let narrow_ruleset_id = *cidr
            .get(&CidrPolicyMapKey::V4(narrow_key))
            .expect("expected narrow key");

        let broad_80_key = PolicyRuleKey {
            ruleset_id: broad_ruleset_id,
            proto: PolicyProtocol::Tcp.into(),
            _pad0: [0; 3],
            port: 80,
            _pad1: [0; 2],
        };
        let broad_443_key = PolicyRuleKey {
            ruleset_id: broad_ruleset_id,
            proto: PolicyProtocol::Tcp.into(),
            _pad0: [0; 3],
            port: 443,
            _pad1: [0; 2],
        };
        assert!(rules.contains_key(&broad_80_key));
        assert!(!rules.contains_key(&broad_443_key));

        let narrow_80_key = PolicyRuleKey {
            ruleset_id: narrow_ruleset_id,
            proto: PolicyProtocol::Tcp.into(),
            _pad0: [0; 3],
            port: 80,
            _pad1: [0; 2],
        };
        let narrow_443_key = PolicyRuleKey {
            ruleset_id: narrow_ruleset_id,
            proto: PolicyProtocol::Tcp.into(),
            _pad0: [0; 3],
            port: 443,
            _pad1: [0; 2],
        };
        assert!(rules.contains_key(&narrow_80_key));
        assert!(rules.contains_key(&narrow_443_key));
    }

    #[test]
    fn reconcile_ingress_ipblock_does_not_expand_to_pod_identity() {
        let target_identity = Identity::new(
            "ident-a",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("pod".into(), "a".into());
                    labels
                },
                id: 701,
            },
        );
        let mut target_identity = target_identity;
        target_identity.metadata.namespace = Some("x".into());

        let source_identity = Identity::new(
            "ident-b",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("pod".into(), "b".into());
                    labels
                },
                id: 702,
            },
        );
        let mut source_identity = source_identity;
        source_identity.metadata.namespace = Some("x".into());

        let pod_b = pod_with_ip(
            "x",
            "pod-b",
            {
                let mut labels = BTreeMap::new();
                labels.insert("pod".into(), "b".into());
                labels
            },
            "10.244.0.6",
        );

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-ipblock-ingress-live-pod".into()),
                namespace: Some("x".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("pod".into(), "a".into());
                        labels
                    }),
                    ..Default::default()
                }),
                ingress: Some(vec![NetworkPolicyIngressRule {
                    from: Some(vec![NetworkPolicyPeer {
                        ip_block: Some(k8s_openapi::api::networking::v1::IPBlock {
                            cidr: "10.244.0.0/24".into(),
                            except: None,
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

        let (pod_store, mut pod_writer) = store::<Pod>();
        let (policy_store, mut policy_writer) = store::<NetworkPolicy>();
        let (identity_store, mut identity_writer) = store::<Identity>();
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

        insert(&mut pod_writer, pod_b);
        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, target_identity.clone());
        insert(&mut identity_writer, source_identity.clone());

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        inner_reconcile_policy_with_identity(Arc::new(target_identity), ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let allow_key = PolicyIndexKey {
            src_id: 702,
            dst_id: 701,
            direction: PolicyDirection::Ingress.into(),
            _pad: [0; 3],
        };
        assert!(!index.contains_key(&allow_key));
    }

    #[test]
    fn reconcile_egress_ipblock_does_not_expand_to_pod_identity() {
        let source_identity = Identity::new(
            "ident-a",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("pod".into(), "a".into());
                    labels
                },
                id: 751,
            },
        );
        let mut source_identity = source_identity;
        source_identity.metadata.namespace = Some("x".into());

        let dst_identity = Identity::new(
            "ident-b",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("pod".into(), "b".into());
                    labels
                },
                id: 752,
            },
        );
        let mut dst_identity = dst_identity;
        dst_identity.metadata.namespace = Some("x".into());

        let pod_b = pod_with_ip(
            "x",
            "pod-b",
            {
                let mut labels = BTreeMap::new();
                labels.insert("pod".into(), "b".into());
                labels
            },
            "10.244.0.6",
        );

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-ipblock-egress-live-pod".into()),
                namespace: Some("x".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("pod".into(), "a".into());
                        labels
                    }),
                    ..Default::default()
                }),
                egress: Some(vec![NetworkPolicyEgressRule {
                    to: Some(vec![NetworkPolicyPeer {
                        ip_block: Some(k8s_openapi::api::networking::v1::IPBlock {
                            cidr: "10.244.0.0/24".into(),
                            except: None,
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

        let (pod_store, mut pod_writer) = store::<Pod>();
        let (policy_store, mut policy_writer) = store::<NetworkPolicy>();
        let (identity_store, mut identity_writer) = store::<Identity>();
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

        insert(&mut pod_writer, pod_b);
        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, source_identity.clone());
        insert(&mut identity_writer, dst_identity.clone());

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        inner_reconcile_policy_with_identity(Arc::new(source_identity), ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let allow_key = PolicyIndexKey {
            src_id: 751,
            dst_id: 752,
            direction: PolicyDirection::Egress.into(),
            _pad: [0; 3],
        };
        assert!(!index.contains_key(&allow_key));
    }

    #[test]
    fn reconcile_egress_ipblock_excludes_matching_pod_identity_when_in_except() {
        let source_identity = Identity::new(
            "ident-a",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("pod".into(), "a".into());
                    labels
                },
                id: 801,
            },
        );
        let mut source_identity = source_identity;
        source_identity.metadata.namespace = Some("x".into());

        let dst_identity = Identity::new(
            "ident-b",
            IdentitySpec {
                namespace_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("env".into(), "prod".into());
                    labels
                },
                pod_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert("pod".into(), "b".into());
                    labels
                },
                id: 802,
            },
        );
        let mut dst_identity = dst_identity;
        dst_identity.metadata.namespace = Some("x".into());

        let pod_b = pod_with_ip(
            "x",
            "pod-b",
            {
                let mut labels = BTreeMap::new();
                labels.insert("pod".into(), "b".into());
                labels
            },
            "10.244.0.6",
        );

        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-ipblock-egress-live-pod".into()),
                namespace: Some("x".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut labels = BTreeMap::new();
                        labels.insert("pod".into(), "a".into());
                        labels
                    }),
                    ..Default::default()
                }),
                egress: Some(vec![NetworkPolicyEgressRule {
                    to: Some(vec![NetworkPolicyPeer {
                        ip_block: Some(k8s_openapi::api::networking::v1::IPBlock {
                            cidr: "10.244.0.0/24".into(),
                            except: Some(vec!["10.244.0.0/28".into()]),
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

        let (pod_store, mut pod_writer) = store::<Pod>();
        let (policy_store, mut policy_writer) = store::<NetworkPolicy>();
        let (identity_store, mut identity_writer) = store::<Identity>();
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

        insert(&mut pod_writer, pod_b);
        insert(&mut policy_writer, policy);
        insert(&mut identity_writer, source_identity.clone());
        insert(&mut identity_writer, dst_identity.clone());

        let policy_bpf_state = TestPolicyBpfState::new();
        let index_state = policy_bpf_state.index_state().unwrap();
        let ruleset_state = policy_bpf_state.ruleset_state().unwrap();
        let ruleset_state = RulesetState::new(&index_state, &ruleset_state);

        let ctx = Context {
            pod_store,
            policy_store,
            identity_store,
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        inner_reconcile_policy_with_identity(Arc::new(source_identity), ctx.clone()).unwrap();

        let index = ctx.policy_bpf_state.index_state().unwrap();
        let allow_key = PolicyIndexKey {
            src_id: 801,
            dst_id: 802,
            direction: PolicyDirection::Egress.into(),
            _pad: [0; 3],
        };
        assert!(!index.contains_key(&allow_key));
    }

    #[test]
    fn cidr_prefixes_for_ip_block_matches_cidr_identity() {
        let ip_block = k8s_openapi::api::networking::v1::IPBlock {
            cidr: "10.244.0.0/24".into(),
            except: None,
        };
        let cidr_identity = CIDRIdentity::new(
            "cidr-10-244-0-0-24-test",
            CidrIdentitySpec {
                id: 990,
                cidr_prefixes: vec!["10.244.0.0/24".into()],
                cidr: Some("10.244.0.0/24".into()),
                except: vec![],
            },
        );

        let prefixes = cidr_prefixes_for_ip_block(&ip_block, &[Arc::new(cidr_identity)]);
        assert_eq!(
            prefixes,
            vec![IpNetwork::from_str("10.244.0.0/24").unwrap()]
        );
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
        let (cidr_identity_store, _cidr_identity_writer) = store::<CIDRIdentity>();
        let (mesh_identity_slice_store, _mesh_identity_slice_writer) = store::<MeshIdentitySlice>();

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
            cidr_identity_store,
            mesh_identity_slice_store,
            policy_bpf_state,
            ruleset_state,
        };

        let ctx = Arc::new(ctx);
        let identity = Arc::new(identity);
        inner_reconcile_policy_with_identity(identity.clone(), ctx.clone()).unwrap();

        let index_before = ctx.policy_bpf_state.index_state().unwrap();
        let idx_key = PolicyIndexKey {
            src_id: ANY_ID,
            dst_id: 31,
            direction: PolicyDirection::Ingress.into(),
            _pad: [0; 3],
        };
        let old_ruleset_id = *index_before
            .get(&idx_key)
            .expect("expected initial ingress entry");

        insert(&mut policy_writer, policy_v2);
        inner_reconcile_policy_with_identity(identity.clone(), ctx.clone()).unwrap();
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
