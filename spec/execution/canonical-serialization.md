# 5H Protocol – Canonical JSON Serialization Standard

**File:** `spec/execution/canonical-serialization.md`  
**Status:** Normative for v0.3 and later  
**Authors:** Claude (Anthropic) – definition; Gemini (Google) – RFC 8785 recommendation  
**Applies to:** All Ed25519 signatures over `ContactRequest` payloads

---

## 1. Purpose

This document defines the canonical form of a `ContactRequest` for signing and verification. Both the Rust core (signer) and the Python proxy (verifier) MUST use this exact algorithm to compute the signing input. Any deviation will cause all signature verifications to fail.

The goal is a deterministic, language-independent serialization that eliminates ambiguity in key ordering, whitespace, and number formatting.

---

## 2. Algorithm

### Step 1 – Remove the signature field

Start with the full `ContactRequest` JSON object. Remove the `"signature"` key and its value entirely. If `"requester_public_key_b64"` is present, keep it.

```json
// Input (full request):
{
  "request_id": "...",
  "signature": "...",
  "requester_public_key_b64": "...",
  ...
}

// After removal:
{
  "request_id": "...",
  "requester_public_key_b64": "...",
  ...
}
```

### Step 2 – Apply RFC 8785 canonicalization

Serialize the signature-free object using RFC 8785 (JSON Canonicalization Scheme, https://www.rfc-editor.org/rfc/rfc8785). The rules are:

1. **Key ordering:** Object keys sorted lexicographically by Unicode code point (not locale-specific).
2. **No insignificant whitespace:** No spaces or newlines between tokens.
3. **String encoding:** All strings encoded as UTF-8. Non-ASCII characters use `\uXXXX` escapes only where required by JSON spec.
4. **Number formatting:** No trailing zeros, no leading zeros. Integers as integers. Floats in shortest-round-trip form.
5. **Recursive:** Arrays and nested objects apply the same rules recursively. Array order is preserved.
6. **No BOM.**

Reference implementations:
- Rust: `json-canon` crate (`serde_json` + custom serializer), or `rfc8785` crate
- Python: `canonicaljson` library, or manual implementation (see Section 4)
- TypeScript: `canonicalize` npm package

### Step 3 – SHA-256 hash

Compute `SHA-256` of the UTF-8 bytes of the RFC 8785 output from Step 2.

```
signing_input = SHA-256(RFC8785(ContactRequest_without_signature))
```

### Step 4 – Ed25519 sign

Sign the 32-byte `signing_input` hash with the requester's Ed25519 private key.

```
signature_bytes = ed25519_sign(private_key, signing_input)
```

### Step 5 – Encode

Base64url-encode the 64-byte signature (no padding required, but accepted).

```
"signature": base64url(signature_bytes)
```

---

## 3. Verification (Python proxy)

```python
import hashlib, json, base64

def canonical_signing_input(request_dict: dict) -> bytes:
    without_sig = {k: v for k, v in request_dict.items() if k != "signature"}
    # RFC 8785: sort_keys=True, no spaces, separators=(',', ':')
    canonical = json.dumps(without_sig, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).digest()
```

**Note on Python's json.dumps vs full RFC 8785:** Python's `json.dumps(sort_keys=True, separators=(",",":"))` satisfies the key-ordering, whitespace, and string-encoding requirements for all inputs that do not contain special float values (NaN, Infinity) or numbers outside IEEE 754 double precision. For a full RFC 8785 implementation, use the `canonicaljson` library. For the 5H Protocol v0.3 reference implementation, `json.dumps` with the parameters above is sufficient because `ContactRequest` contains only strings, integers, arrays of objects, and nested objects — no floats.

---

## 4. Test Vectors

These test vectors allow Branch 1 (Rust) and Branch 2 (Python) to independently verify their implementations produce identical canonical forms.

### Vector 1 – Minimal request

**Input (Python dict / Rust serde_json Value):**
```json
{
  "encryption": "aes-256-gcm",
  "hop_number": 1,
  "intent": {
    "anonymity_level": "identified",
    "intent_type": "professional_inquiry",
    "summary": "Test"
  },
  "preferred_outcome": "forward",
  "request_id": "01900000-0000-7000-8000-000000000001",
  "requester_did": "did:5h:alice",
  "requester_public_key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "target_did": "did:5h:margaret",
  "ttl_hops": 5
}
```

**RFC 8785 canonical form (no whitespace, keys sorted):**
```
{"encryption":"aes-256-gcm","hop_number":1,"intent":{"anonymity_level":"identified","intent_type":"professional_inquiry","summary":"Test"},"preferred_outcome":"forward","request_id":"01900000-0000-7000-8000-000000000001","requester_did":"did:5h:alice","requester_public_key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","target_did":"did:5h:margaret","ttl_hops":5}
```

**SHA-256 of canonical form (hex):**
```
# Implementations must compute this and compare. The exact value depends on
# the canonical bytes above — both implementations must produce the same hex.
# Reference: echo -n '<canonical>' | sha256sum
```

**Validation procedure:**
1. Each implementation independently serializes the input to canonical form
2. Computes SHA-256
3. Compares hex output
4. If outputs match, implementations are compatible

### Vector 2 – Key ordering stress test

**Input:**
```json
{"z_last": 1, "a_first": 2, "m_middle": {"z": 3, "a": 4}}
```

**Expected canonical form:**
```
{"a_first":2,"m_middle":{"a":4,"z":3},"z_last":1}
```

Implementations that do not sort recursively will fail this vector.

### Vector 3 – Unicode passthrough

**Input:**
```json
{"summary": "Möte om 5H-protokollet"}
```

**Expected canonical form:**
```
{"summary":"Möte om 5H-protokollet"}
```

Non-ASCII characters MUST NOT be unnecessarily escaped unless required by the JSON spec.

---

## 5. Rust implementation note

```rust
// Recommended approach for full_flow.rs (v0.3):
// 1. Build the request struct WITHOUT the signature field
// 2. Serialize to canonical JSON
// 3. Hash with SHA-256
// 4. Sign the hash
// 5. Add signature to the final JSON

use sha2::{Sha256, Digest};

let request_without_sig = json!({
    "request_id": request_id,
    "requester_did": "did:5h:alice",
    "requester_public_key_b64": base64url::encode(keys.public_key_bytes()),
    // ... all other fields except "signature"
});

// Step 2+3: canonical JSON + SHA-256
// Use json-canon crate or equivalent RFC 8785 serializer
let canonical = json_canon::to_string(&request_without_sig)?;
let hash = Sha256::digest(canonical.as_bytes());

// Step 4+5: sign and encode
let signature_bytes = keys.sign(&hash);
let signature_b64 = base64url::encode(&signature_bytes);
```

---

## 6. Schema reference

The `requester_public_key_b64` field is defined in `spec/schemas/ai-proxy.json` as an optional string on `ContactRequest`. Its presence enables semantic signature verification in the Python proxy. Its absence causes the proxy to fall back to structural-only verification (or reject, if `REQUIRE_SEMANTIC_VERIFICATION=true`).

---

*This document is normative from v0.3. Implementations claiming v0.3 compliance MUST pass all test vectors in Section 4.*
