"""
five_h_proxy/verification.py

Ed25519 signature verification for incoming ContactRequests.

Current capability: STRUCTURAL verification only.
  - Checks that `signature` is valid base64url
  - Checks that it decodes to exactly 64 bytes (Ed25519 signature length)
  - Rejects clearly malformed signatures
  - Accepts structurally valid signatures with a logged warning

Why not full semantic verification yet:
  Branch 1 (Rust core, v0.2) signs over b"full-flow-request" — a hardcoded
  placeholder, not the canonical JSON of the request. The requester keypair is
  ephemeral and not registered in any DID-to-public-key store. We cannot verify
  the signature content without both:
    1. An agreed canonical signing input (sha256 of ContactRequest JSON minus
       the signature field)
    2. The requester's public key, either embedded in the request or looked up
       from a DID registry

  TODO(v0.3 — branch sync required):
    When Branch 1 implements a public key registry or embeds requester_public_key
    in the ContactRequest payload:
    1. Update verify_request_signature() to call _verify_ed25519()
    2. Add the requester_public_key field to models.ContactRequest (optional, for
       v0.2 compatibility)
    3. Define canonical signing input as:
         sha256(json.dumps(request_dict_without_signature, sort_keys=True))
    4. Remove the structural-only warning log

This follows the same explicit-TODO pattern as the trust layer injection list.

Authors: Claude (Anthropic)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

_ED25519_SIG_BYTES = 64


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


def _decode_base64url(value: str) -> bytes | None:
    """Decode a base64url string (with or without padding). Returns None on failure."""
    try:
        # Add padding if needed
        padding = 4 - len(value) % 4
        if padding != 4:
            value += "=" * padding
        return base64.urlsafe_b64decode(value)
    except Exception:
        return None


def _verify_ed25519(
    public_key_bytes: bytes,
    message: bytes,
    signature_bytes: bytes,
) -> bool:
    """
    Verify an Ed25519 signature. Returns True if valid, False otherwise.
    Used in TODO(v0.3) path once public keys are available.
    """
    try:
        pub_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub_key.verify(signature_bytes, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def _canonical_signing_input(request_dict: dict) -> bytes:
    """
    Canonical signing input for a ContactRequest.
    Defined as sha256(json.dumps(request_without_signature, sort_keys=True)).
    This is the agreed standard for v0.3 semantic verification.
    """
    without_sig = {k: v for k, v in request_dict.items() if k != "signature"}
    canonical = json.dumps(without_sig, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).digest()


def verify_request_signature(
    signature_str: str,
    requester_did: str,
    requester_public_key_b64: str | None = None,
    request_dict: dict | None = None,
) -> SignatureVerificationResult:
    """
    Verify a ContactRequest signature.

    Current mode: structural only.
    Future mode (v0.3): full semantic verification when requester_public_key_b64
    and request_dict are provided.

    Args:
        signature_str: the raw signature field from the ContactRequest
        requester_did: for logging; not used in verification yet
        requester_public_key_b64: base64url-encoded requester public key (optional)
        request_dict: the full request as a dict, for canonical input (optional)

    Returns:
        SignatureVerificationResult
    """
    # --- Structural check ---
    sig_bytes = _decode_base64url(signature_str)

    if sig_bytes is None:
        return SignatureVerificationResult(
            ok=False,
            structural=False,
            semantic=None,
            detail=f"signature is not valid base64url (requester={requester_did})",
        )

    if len(sig_bytes) != _ED25519_SIG_BYTES:
        return SignatureVerificationResult(
            ok=False,
            structural=False,
            semantic=None,
            detail=(
                f"signature has wrong length: expected {_ED25519_SIG_BYTES} bytes, "
                f"got {len(sig_bytes)} (requester={requester_did})"
            ),
        )

    # --- Semantic check (v0.3 path) ---
    if requester_public_key_b64 is not None and request_dict is not None:
        pub_bytes = _decode_base64url(requester_public_key_b64)
        if pub_bytes is None or len(pub_bytes) != 32:
            return SignatureVerificationResult(
                ok=False,
                structural=True,
                semantic=False,
                detail=f"requester_public_key_b64 is not a valid 32-byte Ed25519 public key",
            )
        message = _canonical_signing_input(request_dict)
        valid = _verify_ed25519(pub_bytes, message, sig_bytes)
        if not valid:
            return SignatureVerificationResult(
                ok=False,
                structural=True,
                semantic=False,
                detail=f"Ed25519 signature verification failed (requester={requester_did})",
            )
        return SignatureVerificationResult(
            ok=True,
            structural=True,
            semantic=True,
            detail="signature verified",
        )

    # --- Structural-only path (current v0.2 behaviour) ---
    # TODO(v0.3): remove this warning branch once semantic verification is wired in.
    logger.warning(
        "structural-only signature check for requester=%s. "
        "Semantic verification requires requester_public_key and agreed signing input. "
        "See five_h_proxy/verification.py TODO(v0.3).",
        requester_did,
    )
    return SignatureVerificationResult(
        ok=True,
        structural=True,
        semantic=None,
        detail="structural check passed; semantic verification deferred (v0.3)",
    )
