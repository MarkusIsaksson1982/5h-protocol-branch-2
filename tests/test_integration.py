"""
tests/test_integration.py

Integration tests that simulate the exact payload shape Branch 1's
full_flow.rs sends to /v1/proxy/forward.

Goals:
  1. Verify our server accepts Branch 1's request format without error
  2. Verify structural signature verification works (and fails correctly
     on malformed sigs)
  3. Verify the response is a valid ProxyResponse (not the TemporalProxy
     generic dict that Branch 1's mock returned)
  4. Document the v0.3 semantic verification gap explicitly

Run: pytest tests/test_integration.py -v

Authors: Claude (Anthropic)
"""

from __future__ import annotations

import base64
import os
import uuid

import pytest
from fastapi.testclient import TestClient

from five_h_proxy.proxy import MODEL_VERSION_HASH, app
from five_h_proxy.models import ProxyDecision, ErrorCode, FailureClass

client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers: build payloads matching full_flow.rs output
# ---------------------------------------------------------------------------

def _real_sig_b64(data: bytes = b"full-flow-request") -> str:
    """
    Generate a real Ed25519 signature matching Branch 1's pattern.
    Branch 1 signs b"full-flow-request" with an ephemeral keypair.
    We generate our own ephemeral keypair here for structural testing.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private_key = Ed25519PrivateKey.generate()
    sig = private_key.sign(data)
    return base64.urlsafe_b64encode(sig).decode()


def _rust_payload(**overrides) -> dict:
    """Build the canonical Branch 1 request shape."""
    base = {
        "request_id": str(uuid.uuid4()),
        "requester_did": "did:5h:alice",
        "target_did": "did:5h:margaret",
        "hop_number": 1,
        "intent": {
            "intent_type": "professional_inquiry",
            "summary": "Requesting a meeting about the 5H Protocol implementation",
            "anonymity_level": "identified",
        },
        "preferred_outcome": "forward",
        "consent_receipts": [],
        "signature": _real_sig_b64(),
        "encryption": "aes-256-gcm",
        # ttl_hops absent — defaults to 5 in our model
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Core compatibility tests
# ---------------------------------------------------------------------------

class TestBranch1PayloadCompatibility:
    """Verify our server accepts Branch 1's exact request shape."""

    def test_branch1_payload_accepted(self):
        """Branch 1 full_flow.rs payload must be accepted without 500 errors."""
        resp = client.post("/v1/proxy/forward", json=_rust_payload())
        assert resp.status_code == 200
        data = resp.json()
        # Must return a ProxyResponse, not a TemporalProxy generic dict
        assert "decision" in data
        assert "consent_receipt" in data
        assert "request_id" in data

    def test_response_is_not_temporal_proxy_format(self):
        """Verify we are NOT returning Branch 1's mock proxy format."""
        resp = client.post("/v1/proxy/forward", json=_rust_payload())
        data = resp.json()
        # TemporalProxy returns {"success": True, "data": {...}, "request_id": ...}
        # Our response never has a "success" key at top level
        assert "success" not in data
        assert "workflow_id" not in data
        assert "hops" not in data  # TemporalProxy returned "hops" not "decision"

    def test_consent_receipt_is_present_and_signed(self):
        """Consent receipt must be present and contain a real Ed25519 signature."""
        resp = client.post("/v1/proxy/forward", json=_rust_payload())
        data = resp.json()
        receipt = data["consent_receipt"]
        assert receipt["proxy_did"] == "did:5h:proxy-branch2-ref"
        assert len(receipt["action_hash"]) == 64  # SHA-256 hex
        # Signature must be base64url, not a 64-char hex string
        sig = receipt["signature"]
        assert len(sig) > 64
        import re
        assert re.match(r"^[A-Za-z0-9_=-]+$", sig)

    def test_missing_ttl_hops_defaults_correctly(self):
        """Branch 1 does not send ttl_hops; our default (5) must apply."""
        payload = _rust_payload()
        assert "ttl_hops" not in payload
        resp = client.post("/v1/proxy/forward", json=payload)
        assert resp.status_code == 200
        # If default didn't apply, we'd get a validation error

    def test_professional_inquiry_gets_forward_or_summarize(self):
        """A standard professional inquiry from Alice should forward or summarize."""
        resp = client.post("/v1/proxy/forward", json=_rust_payload())
        data = resp.json()
        assert data["decision"] in [
            ProxyDecision.FORWARD.value,
            ProxyDecision.SUMMARIZE.value,
            ProxyDecision.ACCEPT_AND_CONNECT.value,
        ]


# ---------------------------------------------------------------------------
# Signature verification tests
# ---------------------------------------------------------------------------

class TestSignatureVerification:
    """Structural verification of Ed25519 signatures."""

    def test_valid_real_sig_passes(self):
        resp = client.post("/v1/proxy/forward", json=_rust_payload())
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] != ProxyDecision.REJECT.value

    def test_empty_signature_rejected(self):
        payload = _rust_payload(signature="")
        resp = client.post("/v1/proxy/forward", json=payload)
        # Pydantic may reject before reaching our handler, or our handler rejects
        assert resp.status_code in (200, 422)
        if resp.status_code == 200:
            data = resp.json()
            assert data["decision"] == ProxyDecision.REJECT.value
            assert data["failure_class"] == FailureClass.HARD.value

    def test_wrong_length_signature_rejected(self):
        """A 32-byte (not 64-byte) signature must be rejected."""
        short_sig = base64.urlsafe_b64encode(b"x" * 32).decode()
        payload = _rust_payload(signature=short_sig)
        resp = client.post("/v1/proxy/forward", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == ProxyDecision.REJECT.value
        assert data["error"]["code"] == ErrorCode.POLICY_VIOLATION.value
        assert data["failure_class"] == FailureClass.HARD.value

    def test_non_base64_signature_rejected(self):
        """A plaintext string as signature must be rejected."""
        payload = _rust_payload(signature="this is not base64!")
        resp = client.post("/v1/proxy/forward", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == ProxyDecision.REJECT.value

    def test_v03_semantic_gap_is_documented(self):
        """
        Confirm that a structurally valid sig from a DIFFERENT keypair is accepted.
        This documents the v0.3 gap: we cannot reject semantically invalid sigs yet.
        Once Branch 1 publishes requester public keys, this test should be updated
        to assert rejection.
        """
        # Sign with a different keypair — structurally valid but semantically wrong
        different_sig = _real_sig_b64(b"different-payload")
        payload = _rust_payload(signature=different_sig)
        resp = client.post("/v1/proxy/forward", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        # Currently accepted (structural-only). Mark this explicitly.
        # TODO(v0.3): assert data["decision"] == ProxyDecision.REJECT.value
        assert data["decision"] != ProxyDecision.REJECT.value, (
            "Semantic verification not yet enabled. "
            "See five_h_proxy/verification.py TODO(v0.3)."
        )


# ---------------------------------------------------------------------------
# Health endpoint — public key exposure
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_returns_model_hash_and_pubkey(self):
        resp = client.get("/v1/proxy/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert len(data["model_version_hash"]) == 64
        # public_key_b64 must be a valid base64url string decoding to 32 bytes
        pub_b64 = data.get("public_key_b64", "")
        assert pub_b64, "public_key_b64 must be present in health response"
        raw = base64.urlsafe_b64decode(pub_b64 + "==")
        assert len(raw) == 32, f"Ed25519 public key must be 32 bytes, got {len(raw)}"

    def test_health_endpoint_path(self):
        """Branch 1's compose uses /v1/proxy/health not /health."""
        resp = client.get("/v1/proxy/health")
        assert resp.status_code == 200

    def test_generic_health_path_absent(self):
        """Ensure we don't accidentally expose Branch 1's mock /health endpoint."""
        resp = client.get("/health")
        # Should 404 — we only have /v1/proxy/health
        assert resp.status_code == 404
