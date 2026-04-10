"""
five_h_proxy/verification.py

Ed25519 signature verification for incoming ContactRequests.

Three verification modes, selected at runtime:

  STRUCTURAL (always available)
    Checks that `signature` is valid base64url and decodes to 64 bytes.
    Accepts structurally valid signatures with a logged warning.
    Error: POLICY_VIOLATION / HARD on structural failure.

  SEMANTIC (when requester_public_key_b64 is present in the request)
    Verifies the Ed25519 signature against:
      SHA-256(RFC8785(ContactRequest_without_signature_field))
    See spec/execution/canonical-serialization.md for the exact algorithm.
    Error: POLICY_VIOLATION / HARD on semantic failure.

  ENFORCEMENT (when REQUIRE_SEMANTIC_VERIFICATION=true env var is set)
    Rejects any request that lacks requester_public_key_b64.
    Forces Branch 1 (and any other client) to supply the key for v0.3.
    Error: POLICY_VIOLATION / HARD with a clear migration message.

Runtime configuration:
  REQUIRE_SEMANTIC_VERIFICATION=false   v0.2 compat: structural only when key absent
  REQUIRE_SEMANTIC_VERIFICATION=true    v0.3 enforcement: reject if key absent

The enforcement env var lets Markus flip the proxy to v0.3 mode for Branch 1
without a code change, via docker-compose.yml environment override.

Authors: Claude (Anthropic)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

_ED25519_SIG_BYTES = 64
_ED25519_PUB_BYTES = 32

# Runtime enforcement flag (Gemini advisory 2026-04-14)
REQUIRE_SEMANTIC_VERIFICATION: bool = (
    os.getenv("REQUIRE_SEMANTIC_VERIFICATION", "false").lower() == "true"
)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

class SignatureVerificationResult:
    __slots__ = ("ok", "structural", "semantic", "detail")

    def __init__(self, *, ok: bool, structural: bool, semantic: bool | None, detail: str) -> None:
        self.ok = ok
        self.structural = structural
        self.semantic = semantic  # None = not attempted
        self.detail = detail

    def __repr__(self) -> str:
        return (
            f"SignatureVerificationResult(ok={self.ok}, structural={self.structural}, "
            f"semantic={self.semantic}, detail={self.detail!r})"
        )


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _decode_base64url(value: str) -> bytes | None:
    """Decode a base64url string (with or without padding). Returns None on failure."""
    try:
        padding = 4 - len(value) % 4
        if padding != 4:
            value += "=" * padding
        return base64.urlsafe_b64decode(value)
    except Exception:
        return None


def canonical_signing_input(request_dict: dict) -> bytes:
    """
    Compute the canonical signing input for a ContactRequest.

    Algorithm (spec/execution/canonical-serialization.md):
      1. Remove the "signature" field from the dict
      2. Serialize with RFC 8785-compatible JSON (sort_keys, no whitespace)
      3. SHA-256 hash the UTF-8 bytes

    Python's json.dumps(sort_keys=True, separators=(",",":")) satisfies RFC 8785
    for all ContactRequest field types (strings, integers, arrays, nested objects).
    No floats or special values appear in the schema.
    """
    without_sig = {k: v for k, v in request_dict.items() if k != "signature"}
    canonical = json.dumps(without_sig, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).digest()


def _verify_ed25519(public_key_bytes: bytes, message: bytes, signature_bytes: bytes) -> bool:
    """Verify an Ed25519 signature. Returns True if valid, False on any failure."""
    try:
        pub_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub_key.verify(signature_bytes, message)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


# ---------------------------------------------------------------------------
# Public verification API
# ---------------------------------------------------------------------------

def verify_request_signature(
    signature_str: str,
    requester_did: str,
    requester_public_key_b64: str | None = None,
    request_dict: dict | None = None,
) -> SignatureVerificationResult:
    """
    Verify a ContactRequest signature. Mode selected by available inputs and env config.

    Args:
        signature_str:            raw signature field from ContactRequest
        requester_did:            for logging
        requester_public_key_b64: base64url Ed25519 public key (optional, from request)
        request_dict:             full request as dict, for canonical input computation

    Returns:
        SignatureVerificationResult
    """

    # --- Structural check (always runs first) ---
    sig_bytes = _decode_base64url(signature_str)

    if sig_bytes is None:
        return SignatureVerificationResult(
            ok=False, structural=False, semantic=None,
            detail=f"signature is not valid base64url (requester={requester_did})",
        )

    if len(sig_bytes) != _ED25519_SIG_BYTES:
        return SignatureVerificationResult(
            ok=False, structural=False, semantic=None,
            detail=(
                f"signature has wrong length: expected {_ED25519_SIG_BYTES} bytes, "
                f"got {len(sig_bytes)} (requester={requester_did})"
            ),
        )

    # --- Semantic path: key is present ---
    if requester_public_key_b64 is not None and request_dict is not None:
        pub_bytes = _decode_base64url(requester_public_key_b64)

        if pub_bytes is None or len(pub_bytes) != _ED25519_PUB_BYTES:
            return SignatureVerificationResult(
                ok=False, structural=True, semantic=False,
                detail=(
                    f"requester_public_key_b64 is not a valid {_ED25519_PUB_BYTES}-byte "
                    f"Ed25519 public key (requester={requester_did})"
                ),
            )

        message = canonical_signing_input(request_dict)
        valid = _verify_ed25519(pub_bytes, message, sig_bytes)

        if not valid:
            return SignatureVerificationResult(
                ok=False, structural=True, semantic=False,
                detail=(
                    f"Ed25519 signature does not match SHA-256(RFC8785(request)). "
                    f"Ensure signing input follows spec/execution/canonical-serialization.md "
                    f"(requester={requester_did})"
                ),
            )

        logger.info("semantic Ed25519 verification passed (requester=%s)", requester_did)
        return SignatureVerificationResult(
            ok=True, structural=True, semantic=True,
            detail="Ed25519 signature verified against RFC 8785 canonical input",
        )

    # --- No key present: check enforcement mode ---
    if REQUIRE_SEMANTIC_VERIFICATION:
        return SignatureVerificationResult(
            ok=False, structural=True, semantic=False,
            detail=(
                "REQUIRE_SEMANTIC_VERIFICATION=true but requester_public_key_b64 "
                "is absent from the request. "
                "v0.3 migration required: include requester_public_key_b64 in "
                "ContactRequest and sign SHA-256(RFC8785(request_without_signature)). "
                "See spec/execution/canonical-serialization.md."
            ),
        )

    # --- Structural-only fallback (v0.2 compat) ---
    logger.warning(
        "structural-only signature check for requester=%s "
        "(REQUIRE_SEMANTIC_VERIFICATION=false, requester_public_key_b64 absent). "
        "Set REQUIRE_SEMANTIC_VERIFICATION=true to enforce v0.3 cryptographic standard. "
        "See spec/execution/canonical-serialization.md.",
        requester_did,
    )
    return SignatureVerificationResult(
        ok=True, structural=True, semantic=None,
        detail="structural check passed; semantic verification deferred (set REQUIRE_SEMANTIC_VERIFICATION=true for v0.3)",
    )
