# mesh-cni-policy-controller

`mesh-cni-policy-controller` reconciles Kubernetes NetworkPoliy configuration into eBPF policy maps used by the TC programs attached to network interface(s) in the pod network namespace.

## Controller Flow

```mermaid
flowchart TD
  A[Reconcile Identity] --> B[Select NetworkPolicies that select Identity]
  B --> C[Generate Identity Peer Rules]
  C --> D[Identity Diff and Update Identiy Rulesets Entries]
  D --> E[IPBlock Diff and Update CIDR Rulesets Entries]
```

## Policy Map Layout

`policy_index` and `policy_ruleset` form a two-step lookup for identity-to-identity policy.

`policy_cidr_v4`/`policy_cidr_v6` provide ipBlock policy keyed by selected identity + direction + peer CIDR prefix.

```mermaid
flowchart LR
  subgraph IndexMaps["Index maps"]
    PI["policy_index\nHashMap\nkey: {src_id,dst_id,direction}\nvalue: ruleset_id"]
    PC4["policy_cidr_v4\nLPM Trie\nkey: {prefix_len,selected_id,direction,addr_v4}\nvalue: ruleset_id"]
    PC6["policy_cidr_v6\nLPM Trie\nkey: {prefix_len,selected_id,direction,addr_v6}\nvalue: ruleset_id"]
  end

  PR["policy_ruleset\nHashMap\nkey: {ruleset_id,proto,port}\nvalue: action(allow/deny)"]

  PI --> PR
  PC4 --> PR
  PC6 --> PR
```

Notes:

- For CIDR keys, `prefix_len` is encoded as:
- `64 + ipv4_prefix_bits` for v4
- `64 + ipv6_prefix_bits` for v6
- `selected_id` is the identity the policy selects:
- ingress CIDR rules: selected destination identity
- egress CIDR rules: selected source identity

## Datapath Lookup Model

Current packet policy evaluation in TC:

1. Check conntrack short-circuit as NetworkPolicy is stateful, allow if present.
2. Evaluate identity policy via `policy_index -> policy_ruleset`.
3. Evaluate CIDR policy via `policy_cidr_v4 -> policy_ruleset`.
4. Deny only when both identity and CIDR checks deny.

