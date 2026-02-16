use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use k8s_openapi::api::networking::v1::{IPBlock, NetworkPolicy, NetworkPolicyPeer};
use kube::{
    Api, ResourceExt,
    api::{DeleteParams, Patch, PatchParams},
    runtime::{controller::Action, reflector::ObjectRef},
};
use mesh_cni_crds::v1alpha1::cidridentity::{CIDRIdentity, CidrIdentitySpec};
use mesh_cni_ebpf_common::policy::RESERVED_IDENTITY_IDS;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    Error, Result,
    context::Context,
    controller::{MANANGER, hash_input_name, used_cidr_identity_ids},
};

#[tracing::instrument(skip(ctx, policy))]
pub(crate) async fn reconcile_network_policy(
    policy: Arc<NetworkPolicy>,
    ctx: Arc<Context>,
) -> Result<Action> {
    tracing::info!(
        namespace = %policy.namespace().unwrap_or_default(),
        policy = %policy.name_any(),
        "reconcile cidr identities from network policy state"
    );

    reconcile_cidr_identities(&ctx).await?;

    Ok(Action::requeue(Duration::from_secs(300)))
}

pub(crate) async fn reconcile_cidr_identities(ctx: &Context) -> Result<()> {
    let cidr_identity_api: Api<CIDRIdentity> = Api::all(ctx.client.clone());
    let params = PatchParams::apply(MANANGER).force();

    let mut desired = build_desired_cidr_identities(ctx)?;
    desired.sort_by_key(|a| a.name_any());

    let mut desired_names = HashSet::new();
    for cidr_identity in desired {
        let name = cidr_identity.name_any();
        desired_names.insert(name.clone());
        cidr_identity_api
            .patch(&name, &params, &Patch::Apply(&cidr_identity))
            .await?;
    }

    for existing in ctx.cidr_identities.state() {
        let name = existing.name_any();
        if desired_names.contains(&name) {
            continue;
        }
        cidr_identity_api
            .delete(&name, &DeleteParams::default())
            .await?;
    }

    Ok(())
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize)]
struct CidrIdentityIntent {
    cidr: String,
    except: Vec<String>,
}

fn build_desired_cidr_identities(ctx: &Context) -> Result<Vec<CIDRIdentity>> {
    let mut desired: HashMap<String, CidrIdentitySpec> = HashMap::new();

    for policy in ctx.network_policies.state() {
        for intent in policy_ipblock_intents(&policy) {
            let name = hash_input_name(&intent)?;
            let cidr_prefixes = effective_cidr_prefixes(&intent.cidr, &intent.except)?;

            desired.entry(name).or_insert(CidrIdentitySpec {
                id: 0,
                cidr_prefixes,
                cidr: Some(intent.cidr),
                except: intent.except,
            });
        }
    }

    let mut used_ids = used_cidr_identity_ids(ctx);
    for (name, spec) in &mut desired {
        if let Some(existing) = ctx.cidr_identities.get(&ObjectRef::new(name)) {
            spec.id = existing.spec.id;
            used_ids.insert(spec.id);
        }
    }

    // Allocate deterministic ids in name order so collisions resolve predictably.
    let mut names: Vec<String> = desired.keys().cloned().collect();
    names.sort();
    for name in names {
        let Some(spec) = desired.get_mut(&name) else {
            continue;
        };
        if spec.id != 0 {
            continue;
        }

        let id = deterministic_cidr_identity_id(&name, &used_ids)?;
        spec.id = id;
        used_ids.insert(id);
    }

    Ok(desired
        .into_iter()
        .map(|(name, spec)| CIDRIdentity::new(&name, spec))
        .collect())
}

fn deterministic_cidr_identity_id(name: &str, used_ids: &HashSet<u32>) -> Result<u32> {
    let digest = Sha256::digest(name.as_bytes());

    let mut base_bytes = [0u8; 4];
    base_bytes.copy_from_slice(&digest[..4]);
    let mut candidate = u32::from_be_bytes(base_bytes);

    let mut step_bytes = [0u8; 4];
    step_bytes.copy_from_slice(&digest[4..8]);
    // Odd increment guarantees a full cycle over u32 space with wrapping_add.
    let step = u32::from_be_bytes(step_bytes) | 1;

    let max_probes = used_ids
        .len()
        .saturating_add(RESERVED_IDENTITY_IDS.len())
        .saturating_add(1);

    for _ in 0..max_probes {
        if !RESERVED_IDENTITY_IDS.contains(&candidate) && !used_ids.contains(&candidate) {
            return Ok(candidate);
        }
        candidate = candidate.wrapping_add(step);
    }

    Err(Error::Other(
        "failed to deterministically allocate CIDRIdentity id".into(),
    ))
}

fn policy_ipblock_intents(policy: &NetworkPolicy) -> Vec<CidrIdentityIntent> {
    let mut intents = HashSet::new();

    let Some(spec) = &policy.spec else {
        return Vec::new();
    };

    if let Some(ingress_rules) = &spec.ingress {
        for rule in ingress_rules {
            if let Some(from) = &rule.from {
                add_ipblock_intents(&mut intents, from);
            }
        }
    }

    if let Some(egress_rules) = &spec.egress {
        for rule in egress_rules {
            if let Some(to) = &rule.to {
                add_ipblock_intents(&mut intents, to);
            }
        }
    }

    intents.into_iter().collect()
}

fn add_ipblock_intents(intents: &mut HashSet<CidrIdentityIntent>, peers: &[NetworkPolicyPeer]) {
    for peer in peers {
        let Some(ip_block) = &peer.ip_block else {
            continue;
        };
        intents.insert(ip_block_intent(ip_block));
    }
}

fn ip_block_intent(ip_block: &IPBlock) -> CidrIdentityIntent {
    let mut except = ip_block.except.clone().unwrap_or_default();
    except.sort();
    except.dedup();
    CidrIdentityIntent {
        cidr: ip_block.cidr.clone(),
        except,
    }
}

fn effective_cidr_prefixes(cidr: &str, except: &[String]) -> Result<Vec<String>> {
    let base = IpNetwork::from_str(cidr)
        .map_err(|e| Error::Other(format!("failed to parse cidr {cidr}: {e}")))?;

    let mut remaining = vec![base];
    for excluded in except {
        let excluded = IpNetwork::from_str(excluded).map_err(|e| {
            Error::Other(format!("failed to parse cidr except value {excluded}: {e}"))
        })?;

        let mut next = Vec::new();
        for net in remaining {
            next.extend(subtract_ip_network(net, excluded)?);
        }
        remaining = next;
    }

    let mut prefixes: Vec<String> = remaining.into_iter().map(|n| n.to_string()).collect();
    prefixes.sort();
    prefixes.dedup();
    Ok(prefixes)
}

fn subtract_ip_network(base: IpNetwork, excluded: IpNetwork) -> Result<Vec<IpNetwork>> {
    Ok(match (base, excluded) {
        (IpNetwork::V4(base), IpNetwork::V4(excluded)) => subtract_v4(base, excluded)
            .into_iter()
            .map(IpNetwork::V4)
            .collect::<Vec<_>>(),
        (IpNetwork::V6(base), IpNetwork::V6(excluded)) => subtract_v6(base, excluded)
            .into_iter()
            .map(IpNetwork::V6)
            .collect::<Vec<_>>(),
        _ => {
            return Err(Error::Other(
                "CIDR subtraction cannot mix IPv4 and IPv6 networks".into(),
            ));
        }
    })
}

fn subtract_v4(base: Ipv4Network, excluded: Ipv4Network) -> Vec<Ipv4Network> {
    if !v4_overlaps(base, excluded) {
        return vec![base];
    }
    if v4_contains(excluded, base) {
        return Vec::new();
    }
    if base.prefix() >= 32 {
        return vec![base];
    }

    let Some((left, right)) = split_v4(base) else {
        return vec![base];
    };
    let mut output = subtract_v4(left, excluded);
    output.extend(subtract_v4(right, excluded));
    output
}

fn subtract_v6(base: Ipv6Network, excluded: Ipv6Network) -> Vec<Ipv6Network> {
    if !v6_overlaps(base, excluded) {
        return vec![base];
    }
    if v6_contains(excluded, base) {
        return Vec::new();
    }
    if base.prefix() >= 128 {
        return vec![base];
    }

    let Some((left, right)) = split_v6(base) else {
        return vec![base];
    };
    let mut output = subtract_v6(left, excluded);
    output.extend(subtract_v6(right, excluded));
    output
}

fn split_v4(network: Ipv4Network) -> Option<(Ipv4Network, Ipv4Network)> {
    if network.prefix() >= 32 {
        return None;
    }

    let next_prefix = network.prefix() + 1;
    let start = network.network().to_bits();
    let right_start = start + (1u32 << (32 - next_prefix));

    let left = Ipv4Network::new(Ipv4Addr::from_bits(start), next_prefix).ok()?;
    let right = Ipv4Network::new(Ipv4Addr::from_bits(right_start), next_prefix).ok()?;
    Some((left, right))
}

fn split_v6(network: Ipv6Network) -> Option<(Ipv6Network, Ipv6Network)> {
    if network.prefix() >= 128 {
        return None;
    }

    let next_prefix = network.prefix() + 1;
    let start = network.network().to_bits();
    let right_start = start + (1u128 << (128 - next_prefix));

    let left = Ipv6Network::new(Ipv6Addr::from_bits(start), next_prefix).ok()?;
    let right = Ipv6Network::new(Ipv6Addr::from_bits(right_start), next_prefix).ok()?;
    Some((left, right))
}

fn v4_contains(container: Ipv4Network, candidate: Ipv4Network) -> bool {
    let (container_start, container_end) = v4_bounds(container);
    let (candidate_start, candidate_end) = v4_bounds(candidate);
    container_start <= candidate_start && container_end >= candidate_end
}

fn v4_overlaps(a: Ipv4Network, b: Ipv4Network) -> bool {
    let (a_start, a_end) = v4_bounds(a);
    let (b_start, b_end) = v4_bounds(b);
    a_start <= b_end && b_start <= a_end
}

fn v4_bounds(network: Ipv4Network) -> (u64, u64) {
    let start = network.network().to_bits() as u64;
    let host_bits = 32u32 - u32::from(network.prefix());
    let size = if host_bits == 32 {
        (1u64 << 32) - 1
    } else {
        (1u64 << host_bits) - 1
    };
    (start, start + size)
}

fn v6_contains(container: Ipv6Network, candidate: Ipv6Network) -> bool {
    let (container_start, container_end) = v6_bounds(container);
    let (candidate_start, candidate_end) = v6_bounds(candidate);
    container_start <= candidate_start && container_end >= candidate_end
}

fn v6_overlaps(a: Ipv6Network, b: Ipv6Network) -> bool {
    let (a_start, a_end) = v6_bounds(a);
    let (b_start, b_end) = v6_bounds(b);
    a_start <= b_end && b_start <= a_end
}

fn v6_bounds(network: Ipv6Network) -> (u128, u128) {
    let start = network.network().to_bits();
    let host_bits = 128u32 - u32::from(network.prefix());
    let size = if host_bits == 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    (start, start.saturating_add(size))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use k8s_openapi::api::networking::v1::{NetworkPolicyIngressRule, NetworkPolicySpec};
    use kube::api::ObjectMeta;

    use super::*;

    #[test]
    fn effective_cidr_prefixes_subtracts_except() {
        let prefixes =
            effective_cidr_prefixes("10.0.0.0/8", &["10.0.0.0/9".into()]).expect("prefixes");
        assert_eq!(prefixes, vec!["10.128.0.0/9".to_string()]);
    }

    #[test]
    fn effective_cidr_prefixes_errors_on_mixed_ip_family_except() {
        effective_cidr_prefixes("10.0.0.0/8", &["2001:db8::/32".into()])
            .expect_err("mixed family except should fail");
    }

    #[test]
    fn policy_ipblock_intents_dedupes_except_order() {
        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("np-a".into()),
                namespace: Some("ns-a".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                ingress: Some(vec![NetworkPolicyIngressRule {
                    from: Some(vec![
                        NetworkPolicyPeer {
                            ip_block: Some(IPBlock {
                                cidr: "10.0.0.0/8".into(),
                                except: Some(vec!["10.1.0.0/16".into(), "10.0.0.0/9".into()]),
                            }),
                            ..Default::default()
                        },
                        NetworkPolicyPeer {
                            ip_block: Some(IPBlock {
                                cidr: "10.0.0.0/8".into(),
                                except: Some(vec!["10.0.0.0/9".into(), "10.1.0.0/16".into()]),
                            }),
                            ..Default::default()
                        },
                    ]),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        };

        let intents = policy_ipblock_intents(&policy);
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].cidr, "10.0.0.0/8");
        assert_eq!(
            intents[0].except,
            vec!["10.0.0.0/9".to_string(), "10.1.0.0/16".to_string()]
        );
    }

    #[test]
    fn subtract_ip_network_v4_no_overlap_returns_base() {
        let base = IpNetwork::from_str("10.0.0.0/24").unwrap();
        let excluded = IpNetwork::from_str("10.0.1.0/24").unwrap();

        let result = subtract_ip_network(base, excluded).expect("subtraction should succeed");
        assert_eq!(result, vec![base]);
    }

    #[test]
    fn subtract_ip_network_v4_excluded_contains_base_returns_empty() {
        let base = IpNetwork::from_str("10.0.0.0/24").unwrap();
        let excluded = IpNetwork::from_str("10.0.0.0/16").unwrap();

        let result = subtract_ip_network(base, excluded).expect("subtraction should succeed");
        assert!(result.is_empty());
    }

    #[test]
    fn subtract_ip_network_v4_partial_subtract_splits_prefix() {
        let base = IpNetwork::from_str("10.0.0.0/24").unwrap();
        let excluded = IpNetwork::from_str("10.0.0.0/25").unwrap();

        let result = subtract_ip_network(base, excluded).expect("subtraction should succeed");
        assert_eq!(result, vec![IpNetwork::from_str("10.0.0.128/25").unwrap()]);
    }

    #[test]
    fn subtract_ip_network_v6_partial_subtract_splits_prefix() {
        let base = IpNetwork::from_str("2001:db8::/126").unwrap();
        let excluded = IpNetwork::from_str("2001:db8::/127").unwrap();

        let result = subtract_ip_network(base, excluded).expect("subtraction should succeed");
        assert_eq!(
            result,
            vec![IpNetwork::from_str("2001:db8::2/127").unwrap()]
        );
    }

    #[test]
    fn subtract_ip_network_mixed_family_errors() {
        let base = IpNetwork::from_str("10.0.0.0/24").unwrap();
        let excluded = IpNetwork::from_str("2001:db8::/32").unwrap();

        subtract_ip_network(base, excluded).expect_err("mixed families should error");
    }

    #[test]
    fn deterministic_cidr_identity_id_is_stable() {
        let used_ids = HashSet::new();
        let id_a = deterministic_cidr_identity_id("cidr-a", &used_ids).expect("id");
        let id_b = deterministic_cidr_identity_id("cidr-a", &used_ids).expect("id");
        assert_eq!(id_a, id_b);
    }

    #[test]
    fn deterministic_cidr_identity_id_resolves_collisions_deterministically() {
        let mut used_ids = HashSet::new();
        let first = deterministic_cidr_identity_id("cidr-a", &used_ids).expect("id");
        used_ids.insert(first);

        let second = deterministic_cidr_identity_id("cidr-a", &used_ids).expect("id");
        let second_repeat = deterministic_cidr_identity_id("cidr-a", &used_ids).expect("id");

        assert_ne!(first, second);
        assert_eq!(second, second_repeat);
    }
}
