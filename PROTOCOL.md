# 5H Protocol v0.2 – Frozen Specification (Claude-led Implementation Branch)

**Branch:** `5h-protocol-branch-2` (Claude + ChatGPT/Codex implementation track)  
**Status:** Normative reference for all code in this repository  
**Frozen from:** main repo as of 2026-04-10 (full consolidate_output.txt)  
**Sibling:** `5h-protocol-branch-1` uses an identical frozen spec base  

Sections 1–10 of the specification are identical to the main repo `README.md` v0.1 and are not repeated here. The authoritative normative artifacts for this branch are in `/spec/`:

- `spec/schemas/graph-model.json` — complete node/edge schema including all cross-model additions
- `spec/schemas/ai-proxy.json` — AI proxy wire protocol (ContactRequest, ProxyResponse, ConsentReceipt)
- `spec/threat-model.md` — formal threat model (7 adversary classes, mitigation table)
- `spec/test-vectors/15-node-graph.json` — 15-node synthetic graph; all 10 checklist items are the gate tests

---

### Section 7.1 – AI Proxy Wire Protocol (normative for this branch)

The Python reference server in `implementation/python-proxy/` is the normative implementation of `spec/schemas/ai-proxy.json`. The four required endpoints are:

| Endpoint | Handler |
|---|---|
| `POST /v1/proxy/forward` | `five_h_proxy.proxy.forward` |
| `POST /v1/proxy/redact/{request_id}` | `five_h_proxy.proxy.redact` |
| `GET /v1/proxy/escrow/{token}/approve` | `five_h_proxy.proxy.approve_escrow` |
| `GET /v1/proxy/escrow/{token}/release` | `five_h_proxy.proxy.release_escrow` |
| `GET /v1/proxy/health` | `five_h_proxy.proxy.health` |

The OpenAPI specification is auto-generated from the FastAPI app at `/openapi.json` and will be exported to `spec/openapi/proxy-api.yaml` when the server reaches stable.

---

### Section 11 – Execution & Trust Semantics (normative for this branch)

Mapped from ChatGPT/OpenAI's commentary (execution semantics + H-T trust layer):

The Contact Request Lifecycle (Section 6 of the main spec) is the **deterministic envelope**. Each hop applies transformation `T(Hn)` to the incoming state `S(n)` to produce `S(n+1)`:

```
S(n) = { ContactRequest, ConsentReceiptChain, EscrowState }
T(Hn) = { TrustEvaluation(H-T), RateLimitCheck, PolicyDecision, ReceiptAppend }
S(n+1) = { ProxyResponse, UpdatedReceiptChain }
```

The **H-T Trust Layer** (`five_h_proxy/trust_layer.py`) runs orthogonally before every handler. It implements three ChatGPT-defined check categories with this branch's failure taxonomy:

| Category | Checks | Failure Class |
|---|---|---|
| Structural | TTL, hop count, consent chain order, proxy hash | hard |
| Semantic | Intent/summary consistency | soft |
| Alignment | Prompt injection, adversarial pattern detection | critical |

Failure classes map to abort behavior:
- `soft` — reject with guidance; requester may retry with modifications
- `hard` — reject and signal chain rollback
- `critical` — reject, log incident, escalate to proxy owner

---

### Section 12 – Branch-2 specific policies

1. **Consent receipt mode default:** `full_chain` (configurable via `RECEIPT_MODE` env var)
2. **Rate limits:** Level-0: 5/hr, Level-1: 100/hr, Level-2: 1000/hr (sliding window)
3. **Escrow TTL:** 7 days; auto-expire without approval
4. **Summarizer:** Identity function (default); replace with model call for production
5. **model_version_hash:** Computed from `sha256(MODEL_ID || "||" || SYSTEM_PROMPT)` at startup; exposed via `/v1/proxy/health`

---

This document is frozen. Changes require a commentary artifact in `commentary/models/claude-anthropic/` describing the proposed change and rationale before any code is modified.

**Signed:** Claude, Anthropic (branch lead)  
**Co-signed:** ChatGPT / Codex, OpenAI (primary collaborator)
