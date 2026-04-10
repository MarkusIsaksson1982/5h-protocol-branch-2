# 5H Protocol – Threat Model v0.1

**Timestamp:** 2026-04-10T14:50:00+02:00 (CEST)  
**Model:** Claude – Anthropic  
**Model family:** Claude (Anthropic)  
**Purpose:** Formal threat model identified by both Grok and Muse Spark as a required missing piece; authored as a direct technical contribution to the spec roadmap.  
**Companion to:** `2026-04-10T14-30-00+02-00_claude-initial-review.md`  
**Intended repo location:** `spec/threat-model.md` (or Section 11 of PROTOCOL.md)

---

## 1. Scope

This threat model covers the 5H Protocol as specified in `README.md` v0.1 and the AI Proxy Wire Protocol defined in `grok-xai/2026-04-10T00-31-00+02-00_grok-ai-proxy-wire-protocol.md`. It follows a standard adversary–goal–mitigation structure. It does not cover vulnerabilities in downstream client implementations, the underlying DID/IPFS/blockchain infrastructure, or physical-layer attacks.

---

## 2. Assets to Protect

| Asset | Sensitivity | Notes |
|---|---|---|
| Social graph topology | **High** | Who knows whom is often more sensitive than message content |
| Message intent and content | **High** | Even summarized intent can be re-identifying in context |
| Existence of a path between two DIDs | **Medium** | Confirms social proximity; useful for targeting |
| Identity of intermediary nodes | **Medium** | Leaks graph structure hop by hop |
| Verification level of nodes | **Medium** | Reveals identity-verification posture; enables tier-targeted attacks |
| AI proxy system prompts and configurations | **Medium** | Can reveal organizational priorities, biases, or exploitable constraints |
| Consent receipt chains | **Low–Medium** | Valuable for accountability; dangerous if aggregated across many requests |
| Existence of blocklist entries | **Low** | Still reveals relationship history |

---

## 3. Adversary Classes

### A1 – Spam and Commercial Harvester
**Goal:** Reach as many targets as possible with minimal friction; bypass consent or exhaust intermediary patience.  
**Capabilities:** Can register many Level-0 nodes; can automate request initiation at scale; may operate AI proxies for automated forwarding.  
**Constraints:** Cannot forge verification levels without compromising Level-1/2 providers; blocked by per-tier rate limits if implemented.

### A2 – Stalker or Targeted Harasser
**Goal:** Locate and contact a specific individual who has blocked or hidden their profile.  
**Capabilities:** May hold legitimate Level-1+ verification; may share mutual connections with the target; can craft intent descriptions that appear benign.  
**Constraints:** Cannot force a node to forward; cannot see profiles below their own visibility clearance; single-hop blocking limits direct paths.

### A3 – Graph Topology Adversary
**Goal:** Map the social graph of individuals or organizations without their knowledge or consent.  
**Capabilities:** Can issue many reachability queries from multiple identities; can correlate timing signals and success/failure rates to infer graph structure.  
**Constraints:** Cannot directly read other users' edge lists; cannot see identities of intermediaries in normal operation.

### A4 – Malicious AI Proxy Operator
**Goal:** Insert a proxy that appears neutral but logs requests, manipulates summaries, selectively routes to preferred targets, or exfiltrates relationship data.  
**Capabilities:** Can register a legitimate-looking AI proxy with a compliant declared system prompt; can substitute a different runtime configuration after consent is granted.  
**Constraints:** Cannot act as a proxy unless both requester and target opt in to the specific registered proxy; owner DID is attributed to every action.

### A5 – State Actor or Institutional Coercion
**Goal:** Compel an org node, bridge operator, or infrastructure provider to reveal routing information, block specific paths, or de-anonymize participants.  
**Capabilities:** Legal authority over organizations within their jurisdiction; may directly control bridge operators or hosting infrastructure.  
**Constraints:** Cannot compel nodes outside their jurisdiction; cryptographic receipts may make coercion attempts visible; federated architecture distributes legal exposure.

### A6 – Sybil Attacker
**Goal:** Inflate apparent network reach (artificially reduce degrees of separation to high-value targets) by creating many fake nodes.  
**Capabilities:** Can register an arbitrary number of Level-0 nodes at low cost.  
**Constraints:** Level-0 nodes are blocked by org-level verified-only policies; vouch-limited edge creation (if adopted) caps effective reach per time period.

### A7 – Insider / Compromised Org Node
**Goal:** Abuse a legitimate org forwarding position to harvest contact data, selectively suppress requests, or surveil employees who pass through the node.  
**Capabilities:** Full visibility into requests routed through the org's internal chain.  
**Constraints:** Subject to org-level audit trails; external nodes see only that the request passed through the org, not internal routing details.

---

## 4. Threat–Mitigation Table

| Threat | Adversary(s) | Current Mitigation in v0.1 | Gap | Recommended Addition |
|---|---|---|---|---|
| Bulk spam via Level-0 nodes | A1, A6 | Rate limiting per user and tier; blocklists | No cost signal for Level-0 outbound requests | Vouch-limited edge creation; lightweight proof-of-work or stake requirement for Level-0 request initiation |
| Path enumeration via reachability queries | A3 | Query returns probability estimate + hop count, no identities | Hop count alone leaks distance; repeated queries triangulate the graph | Query rate limiting; differential privacy noise on returned hop count; k-anonymized bloom filter for "can-reach" preflight (per Muse Spark suggestion) |
| Targeted harassment via shared social proximity | A2 | Blocklists; visibility ACLs | A's block of B does not prevent B from routing through A's contacts | Add optional block-propagation: a blocked requester cannot route through the blocker's direct connections without the blocker's explicit re-authorization |
| Malicious proxy runtime substitution | A4 | Dual opt-in; audit trails require owner-DID attribution | Consent is to a registered proxy name, not a specific configuration; operator can update model or prompt silently | Pin system prompt hash at consent time; require re-attestation (new opt-in cycle) when proxy configuration changes; expose `model_version_hash` in proxy profile |
| Consent receipt chain reveals full path | A3, A5 | Not addressed — receipts are currently full chains | Target receives a complete social graph path | Implement onion or blind-signature receipt scheme: each hop verifies chain integrity without seeing prior hop identities; target receives a Merkle root + audit-open mechanism requiring dual consent |
| State coercion of org or bridge nodes | A5 | Federated architecture distributes legal exposure | No defined response protocol or canary mechanism | Recommend multi-jurisdiction federation for high-sensitivity paths; allow nodes to publish a signed canary statement; define a legal-hold response procedure in spec |
| Bridge operators stripping or altering consent metadata | A4, A5 | Bridge contract mentioned but not yet specified | No cryptographic binding between source receipt and bridge relay | Specify minimum consent metadata bridges must preserve; require bridges to sign a relay receipt that binds to the originating consent receipt hash |
| Employee coercion as internal gateway | A5, A7 | Not addressed | Org can designate any employee as a mandatory forwarding node | Add `gateway_consent: "voluntary" | "role_required"` to org node policy; recommend conforming implementations surface this flag to requesters |
| AI proxy accumulating relational data over time | A4 | Per-request dual opt-in | No expiry on proxy authorization; no restriction on what the proxy may store | Add `consent_expiry` timestamp to proxy authorization; prohibit proxy from storing requester or target DIDs beyond request TTL without explicit, separate logging consent |
| Sybil inflation of graph proximity | A6 | Org verified-only policies block Level-0 paths in sensitive contexts | Open to Sybil inflation in Level-0-accessible paths | Vouch budget per Level-1+ node per time window; vouch required for Level-0 edge creation; slow budget restoration rate |
| Insider node harvesting contact metadata | A7 | Org-internal audit trails | Audit trails may be under org control and thus suppressible | Recommend external, append-only audit log anchoring (e.g. Merkle root on L2 chain per Grok's suggestion) even for internal hops; allow users to request proof that their request was forwarded without seeing internal org routing |

---

## 5. Out-of-Scope Threats (noted for future versions)

- **Infrastructure-layer attacks** on the DID registry, IPFS content addressing, or blockchain anchoring. These are attacks against the underlying stack, not the protocol specification.
- **Side-channel attacks on AI proxy inference** (timing, token-count, energy consumption). Require physical proximity or traffic analysis capabilities beyond the protocol's threat surface; addressed by proxy implementation hardening, not the spec.
- **Social engineering of human intermediary nodes.** The protocol cannot prevent a human from being deceived into forwarding a request. This is a client UX and user education problem; the spec should note it explicitly as out of scope for the protocol itself while recommending that client implementations surface intent summaries and requester verification levels clearly.
- **Cryptographic breaks** to Ed25519 or the ZK proof schemes. The protocol's recommendation to reserve a `key_alg` field for ML-DSA migration (per Muse Spark) is the correct long-term response.

---

## 6. Recommended Additions to the Spec

1. Publish this document as `spec/threat-model.md` and add a reference from README Section 9 (Privacy & Security Considerations).
2. Label each bullet in Section 9 with the adversary class it mitigates (e.g., "Rate limiting [A1, A6]").
3. Define a responsible disclosure policy and security contact address for protocol-level vulnerabilities.
4. Add test vectors to `spec/test-vectors/` that exercise each major threat scenario: a Sybil inflation attempt, a reachability query enumeration sequence, a malicious proxy substitution, and a state-coercion scenario with canary response.
5. Publish the bridge contract specification as a required (not optional) section before v1.0, given that bridge operators are the highest-leverage single points of failure in the federated model.

---

Signed: Claude, Anthropic  
Custodian of `/commentary/models/claude-anthropic/`  
Companion to: `2026-04-10T14-30-00+02-00_claude-initial-review.md`
