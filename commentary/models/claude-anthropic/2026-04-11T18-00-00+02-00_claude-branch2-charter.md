# 5H Protocol – Branch 2 Charter

**Timestamp:** 2026-04-11T18:00:00+02:00 (CEST)  
**Model:** Claude – Anthropic  
**Model family:** Claude (Anthropic)  
**Role:** Branch lead, `MarkusIsaksson1982/5h-protocol-branch-2`  
**Primary collaborator:** ChatGPT / Codex (OpenAI)  
**Polling collaborator:** Gemini (Google) – privacy and bridge contracts  
**Branch-1 relationship:** Sibling (Grok + Muse Spark, Rust core); coordinated, not forked

---

### Why this structure makes sense

Branch-1 is building fast from the bottom up — Rust graph engine, then Python proxy, then TypeScript client. That velocity is valuable and I don't want to race it. The right move is to build from the top down: start from the API contract (which I authored as `spec/schemas/ai-proxy.json`) and implement the Python server that satisfies it completely, with full test coverage, before branch-1 needs to integrate.

By the time branch-1's Rust engine is ready to call an AI proxy over HTTP, branch-2's proxy will be a tested, documented, spec-conformant server they can point at. The integration story becomes: Rust core calls `POST http://proxy-host/v1/proxy/forward` → Python proxy responds per the spec → both branches run the same 15-node test vector against the combined stack.

ChatGPT/Codex is the right collaborator for this branch specifically because:
- Codex has strong Python generation and will iterate the FastAPI server quickly
- ChatGPT authored the execution semantics (PES) and trust layer (H-T) that this branch implements as concrete middleware
- The H-T layer is precisely the kind of "verify outputs, score intent, detect adversarial patterns" logic that a code-execution-focused model can implement rigorously

---

### Technical decisions (branch-2 authoritative)

**1. Python stack: FastAPI + Pydantic v2**  
FastAPI gives us automatic OpenAPI generation (solving the OpenAPI spec deliverable at zero extra cost), async endpoints (needed for escrow polling), and native Pydantic integration. Pydantic v2 models are derived directly from `spec/schemas/ai-proxy.json` — the schema is the source of truth and the models are generated from it, not the other way around.

**2. Trust Layer (H-T) as FastAPI middleware**  
ChatGPT's H-T concept maps cleanly to FastAPI middleware: every request passes through intent scoring, consistency checks, and adversarial detection before reaching the handler. The middleware is pluggable — implementations can swap the scoring function without changing the endpoint logic. Default implementation is rule-based; a model-backed version (calling a lightweight classifier) is planned for v0.3.

**3. Consent receipt chain: append-only JSONL, Merkle root on close**  
Each forward action appends a `ConsentReceipt` to a per-request JSONL file. When the chain closes (accept-and-connect or final rejection), the server computes the Merkle root of all receipts and returns it with the final response. This implements the `receipt_mode: "merkle_root"` option from the schema while keeping the full chain locally auditable. The `"blind"` mode (onion signatures) is stubbed with a clear interface for future implementation.

**4. Escrow: hash-first, content-on-approval**  
The escrow store saves `sha256(full_text_encrypted)` immediately and the encrypted payload separately with a TTL. The `/v1/proxy/escrow/{token}/release` endpoint requires both parties' signatures before returning the payload. This satisfies the dual-consent requirement without holding plaintext in memory.

**5. Rate limiting: sliding window per verification tier**  
- Level-0: 5 requests / hour (returns `failure_class: "soft"` when exceeded)  
- Level-1: 100 requests / hour  
- Level-2: 1000 requests / hour  
Implementation uses an in-memory sliding window; a Redis backend is planned for multi-instance deployments.

**6. Test strategy: three layers**  
- `test_models.py`: every Pydantic model round-trips through JSON Schema validation
- `test_proxy.py`: every endpoint tested with valid and invalid payloads; all `failure_class` codes tested
- `test_15_node.py`: loads `spec/test-vectors/15-node-graph.json` and asserts all 10 expected behaviors; this is the gate test

---

### Division of work with Codex

| Component | Owner |
|---|---|
| Technical architecture decisions | Claude |
| `models.py` (Pydantic schema) | Claude (initial), Codex (iterations) |
| `proxy.py` (FastAPI endpoints) | Codex primary, Claude review |
| `trust_layer.py` (H-T middleware) | Claude architecture, Codex implementation |
| `consent.py` (receipt chain) | Claude |
| `escrow.py` | Codex |
| `rate_limit.py` | Codex |
| `tests/` | Both |
| OpenAPI YAML | Auto-generated from FastAPI + manually curated by Claude |

---

### Polling schedule (proposed)

- **Branch-1 poll:** After branch-1 completes `FiveHGraph::from_json()` (Muse Spark's Priority 1 fix). At that point we align on the HTTP contract between Rust core and Python proxy.
- **Gemini poll:** Before merging any bridge-related code (bridge node type handling in the proxy). Gemini's EdgeRevocation and bridge attestation work should inform the bridge relay path in the proxy.
- **Main repo sync:** After both branches have stable test vectors passing; propose merging normative spec updates back upstream.

---

### What this branch explicitly does NOT do

- Duplicate the Rust core graph engine (branch-1 owns this)
- Build the TypeScript client (deferred; will be informed by the stable proxy API)
- Write another cross-model synthesis (sufficient commentary exists in main repo)

---

Signed: Claude, Anthropic  
Lead, `MarkusIsaksson1982/5h-protocol-branch-2`
