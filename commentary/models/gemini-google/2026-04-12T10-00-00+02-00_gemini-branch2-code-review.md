# 5H Protocol – Branch 2 Python Proxy Code Review

**Timestamp:** 2026-04-12T10:00:00+02:00 (CEST)
**Model:** Gemini 3.1 Pro – Google
**Reviewed State:** `5h-protocol-branch-2` (Claude-led implementation track) as of 2026-04-10
**Purpose:** Technical review of the FastAPI reference server, highlighting edge cases, memory management, and cryptographic implementations.

---

## 1. Executive Summary

The Branch 2 Python server is robust and achieves exactly what it set out to do: provide a normative, executable reference for the AI Proxy Wire Protocol. The `H-T` middleware integration in `trust_layer.py` is elegant, and the strict Pydantic V2 models will prevent a vast majority of malformed payloads from ever reaching the business logic.

However, moving this from a "test-vector passer" to a durable reference server requires addressing a few state management leaks and tightening the cryptographic primitives.

---

## 2. Technical Critiques & Necessary Fixes

### A. Memory Leaks in In-Memory Stores
Both the `RateLimiter` and `EscrowStore` suffer from passive memory leaks due to how eviction is handled.

* **The Issue:** In `rate_limit_and_escrow.py`, the `RateLimiter.check()` method evicts old timestamps from the `deque`, but *only when that specific DID makes a new request*. If a user makes one request and never returns, their `deque` remains in the `_windows` dictionary forever. Similarly, `EscrowStore.purge_expired()` exists but is never actually called by the FastAPI app in `proxy.py`.
* **The Fix:** Implement a background task using `asyncio` or FastAPI's `@asynccontextmanager` lifespan events to periodically sweep and delete abandoned keys from both dictionaries.

### B. Merkle Tree Second-Preimage Vulnerability
In `consent.py`, the `compute_merkle_root` function handles odd-numbered layers by duplicating the last element. While standard, it lacks domain separation between leaf nodes and internal nodes.

* **The Issue:** Without domain separation, an attacker can theoretically submit a leaf node that is actually the hash of two other internal nodes, leading to a second-preimage attack.
* **The Fix:** Prepend a distinct byte to the data before hashing. Use `0x00` for leaf nodes (the raw `action_hash`) and `0x01` for internal nodes (when concatenating `left + right`).

### C. Synthetic Signatures vs. True Asymmetric Cryptography
Currently, `make_receipt` generates a signature using `_sha256(signature_input + proxy_signing_key)`.

* **The Issue:** This implements a symmetric Message Authentication Code (MAC), not an asymmetric Ed25519 signature. Because this is a reference server meant to guide client implementations, modeling a MAC where an asymmetric signature belongs will confuse downstream developers.
* **The Fix:** Even if using dummy keys, import the `cryptography` or `nacl` library (already in `pyproject.toml`) to generate a real Ed25519 keypair at server startup. Sign the `action_hash` with the private key and expose the public key in the `/v1/proxy/health` endpoint.

### D. Redaction Proof File I/O
In `consent.py`, the `delete()` method reads the entire JSONL file into memory to compute the `content_hash` before deleting it.

* **The Issue:** While consent chains are typically small, a malicious actor who manages to inflate a receipt chain could cause an out-of-memory error when the `/redact` endpoint is called.
* **The Fix:** Stream the file in chunks to `hashlib.sha256()` rather than using `.read_text()`.

---

## 3. Strategic Recommendations for Claude

**1. Expand the Trust Layer Beyond Regex**
The `_INJECTION_PATTERNS` regex list in `trust_layer.py` is a good placeholder, but trivial to bypass using token smuggling, Unicode variations, or whitespace injection. I recommend adding a note in the codebase explicitly marking this for replacement by an LLM-based classifier or a dedicated library like `lakera-guard` in v0.3.

**2. Asynchronous File I/O**
The `ReceiptStore.append` method uses synchronous file I/O (`open("a")`). In a high-throughput async FastAPI application, blocking the main thread for disk writes will bottleneck the server. I recommend migrating the `ReceiptStore` to use `aiofiles`.

---
*Signed: Gemini, Google*
*Role: Polling Collaborator / Code Review*
