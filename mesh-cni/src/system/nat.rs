use crate::Result;
use anyhow::Context;
use ipnetwork::IpNetwork;
use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, ProtocolFamily, Rule, Table,
    list_chains_for_table, list_rules_for_chain, list_tables,
};

const TABLE_NAME: &str = "mesh_cni_nat";
const CHAIN_NAME: &str = "postrouting";
const RULE_TAG: &[u8] = b"mesh-cni-pod-snat";
const SRCNAT_PRIORITY: i32 = 100;

pub(crate) fn ensure_pod_snat(pod_cidr: IpNetwork, iface: &str) -> anyhow::Result<()> {
    let family = ProtocolFamily::Inet;
    let mut batch = Batch::new();
    let (table, table_added) = ensure_table(TABLE_NAME, family, &mut batch)?;
    let (chain, chain_added) = ensure_chain(CHAIN_NAME, &table, &mut batch)?;
    let (_, rule_added) = ensure_rule(&chain, RULE_TAG, pod_cidr, iface, &mut batch)?;

    if table_added || chain_added || rule_added {
        batch
            .send()
            .context("failed to apply nftables pod SNAT batch")?;
    }
    Ok(())
}
fn ensure_table(name: &str, family: ProtocolFamily, batch: &mut Batch) -> Result<(Table, bool)> {
    if let Some(table) = list_tables()?
        .into_iter()
        .find(|t| t.get_name().map(String::as_str) == Some(name))
    {
        return Ok((table, false));
    };

    let table = Table::new(family).with_name(name);

    Ok((table.add_to_batch(batch), true))
}

fn ensure_chain(name: &str, table: &Table, batch: &mut Batch) -> Result<(Chain, bool)> {
    if let Some(chain) = list_chains_for_table(table)?
        .into_iter()
        .find(|c| c.get_name().map(String::as_str) == Some(name))
    {
        return Ok((chain, false));
    }

    let chain = Chain::new(table)
        .with_name(name)
        .with_type(ChainType::Nat)
        .with_hook(Hook::new(HookClass::PostRouting, SRCNAT_PRIORITY))
        .with_policy(ChainPolicy::Accept);

    Ok((chain.add_to_batch(batch), true))
}

fn ensure_rule(
    chain: &Chain,
    rule_tag: &[u8],
    pod_cidr: IpNetwork,
    iface: &str,
    batch: &mut Batch,
) -> Result<(Rule, bool)> {
    if let Some(rule) = list_rules_for_chain(chain)?
        .into_iter()
        .find(|r| r.get_userdata().map(|v| v.as_slice()) == Some(rule_tag))
    {
        return Ok((rule, false));
    }

    let rule = Rule::new(chain)?
        .snetwork(pod_cidr)?
        .oiface(iface)?
        .masquerade()
        .with_userdata(rule_tag.to_vec());
    Ok((rule.add_to_batch(batch), true))
}
