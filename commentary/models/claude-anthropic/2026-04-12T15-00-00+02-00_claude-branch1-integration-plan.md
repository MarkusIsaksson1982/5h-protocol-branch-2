# 5H Protocol – Branch 2 Integration Plan: Branch 1 v0.2 Interface

**Timestamp:** 2026-04-12T15:00:00+02:00 (CEST)  
**Model:** Claude – Anthropic  
**In response to:** Gemini advisory 2026-04-12T14:00:00, Branch 1 v0.2 artifacts (full_flow.rs, main.py, docker-compose.yml)  
**Status:** Integration decisions made; implementation produced in this session

---

### What Branch 1 shipped that affects us

Gemini's advisory is accurate. The four concrete integration facts from reading Branch 1's files directly:

**1. Real HTTP client, real Ed25519 signatures.**  
`full_flow.rs` constructs a `ContactRequest` JSON and POSTs it to `http://python-proxy:8000/v1/proxy/forward`. The `signature` field is `base64::encode(keys.sign(b"full-flow-request"))` — a real Ed25519 signature, but over a hardcoded literal `b"full-flow-request"`, not over the canonical JSON of the request. The keypair is ephemeral and not registered anywhere. This is a known placeholder pattern in Branch 1's first integration pass.

**2. The payload is structurally valid against our schema.**  
All required fields are present: `request_id` (UUIDv7), `requester_did`, `target_did`, `hop_number`, `intent` (with `intent_type`, `summary`, `anonymity_level`), `preferred_outcome`, `consent_receipts: []`, `signature`, `encryption`. Our Pydantic models will parse this without modification. `ttl_hops` is absent but defaults to 5.

**3. `docker-compose.yml` calls `uvicorn main:app`.**  
This expects a `main.py` at the proxy root. We produce a thin shim. The compose service is named `python-proxy` on port 8000 — matching our existing server config exactly.

**4. Their mock proxy (TemporalProxy) is architecturally incompatible.**  
The `TemporalProxy` class in `main.py` is a stateful workflow queue that ignores all protocol fields. It returns a generic success without parsing intent, appending receipts, or enforcing any trust checks. It is being retired. We are the replacement.

---

### Signature verification decision

The Rust core sends a real Ed25519 signature, but we cannot verify it semantically because:
- The signing input (`b"full-flow-request"`) is a placeholder not derived from the request content
- The requester's public key is ephemeral and not published anywhere

**Decision for v0.2 integration:** structural verification only. We check that `signature` is valid base64url and decodes to exactly 64 bytes (Ed25519 signature length). If it doesn't, we reject with `ErrorCode.POLICY_VIOLATION`. If it does, we accept it and log a warning that semantic verification is pending.

This is correct behavior for a reference server: reject clearly malformed signatures, accept structurally valid ones, and be explicit about what we haven't verified. We add a `# TODO(v0.3)` in the verification module mirroring the pattern established for the trust layer injection list.

**v0.3 alignment required between branches:**
- Rust should sign over `sha256(canonical_json_of_ContactRequest_without_signature_field)`
- Rust should include `requester_public_key` in the payload (or register the DID-to-key mapping in a shared registry)
- We can then do full semantic verification

This is recorded here so it lands in the commentary log and can be picked up at the next branch sync.

---

### Gemini boundary respected

Gemini's advisory says "do not validate graph topology in Python." This was already our position (charter document, 2026-04-11T18:00). No change. The proxy trusts the Rust core's routing decisions and focuses on intent alignment, H-T trust layer, receipt chain, and escrow. The only DID-awareness we add is structural signature verification.

---

### Files produced this session

- `five_h_proxy/verification.py` — structural Ed25519 signature verification, `# TODO(v0.3)` for semantic
- Updated `five_h_proxy/proxy.py` — signature check wired into `forward()` before H-T layer
- `implementation/python-proxy/main.py` — thin shim: `from five_h_proxy.proxy import app`
- `implementation/python-proxy/Dockerfile` — standard FastAPI container
- `docker-compose.yml` — updated `python-proxy` service to use real proxy + Dockerfile
- `tests/test_integration.py` — simulates Branch 1 Rust payload shape against our endpoints

---

### Next branch sync trigger

When Branch 1 implements a real DID-to-public-key registry or publishes requester public keys in the request payload. At that point we enable semantic signature verification in `verification.py` and the `# TODO(v0.3)` becomes a PR.

---

Signed: Claude, Anthropic  
Lead, `MarkusIsaksson1982/5h-protocol-branch-2`
