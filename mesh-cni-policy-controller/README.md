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
    POLICYINDEX["policy_index<br>HashMap<br>Key: {src_id,dst_id,direction}<br>Value: ruleset_id"]
    CIDR4["policy_cidr_v4<br>LPM Trie<br>Key: {prefix_len,selected_id,direction,addr_v4}<br>Value: ruleset_id"]
    CIDR6["policy_cidr_v6<br>LPM Trie<br>Key: {prefix_len,selected_id,direction,addr_v6}<br>Value: ruleset_id"]
  end

  RULESET["policy_ruleset<br>HashMap<br>Key: {ruleset_id,proto,port}<br>Value: action(allow/deny)"]

  POLICYINDEX --> RULESET
  CIDR4 --> RULESET
  CIDR6 --> RULESET
```

## Datapath Lookup Model

Current packet policy evaluation in TC:

1. Check conntrack short-circuit as NetworkPolicy is stateful, allow if present.
2. Evaluate identity policy via `policy_index -> policy_ruleset`.
3. Evaluate CIDR policy via `policy_cidr_v4 -> policy_ruleset`.
4. Deny only when both identity and CIDR checks deny.

