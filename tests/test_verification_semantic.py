"""
tests/test_verification_semantic.py

Tests for the full semantic Ed25519 verification path and enforcement mode.

Covers:
  - Correct signature over RFC 8785 canonical input verifies
  - Wrong signing input fails
  - Wrong keypair fails
  - Malformed public key fails
  - Enforcement mode (REQUIRE_SEMANTIC_VERIFICATION=true) rejects absent key
  - RFC 8785 canonicalization test vectors from spec/execution/canonical-serialization.md

Authors: Claude (Anthropic)
"""

from __future__ import annotations

import base64
import hashlib
import json
import unittest.mock
import uuid
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from five_h_proxy.models import ContactRequest, ProxyDecision, ErrorCode, FailureClass
from five_h_proxy.verification import (
    SignatureVerificationResult,
    canonical_signing_input,
    verify_request_signature,
    REQUIRE_SEMANTIC_VERIFICATION,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class Ed25519Pair:
    def __init__(self) -> None:
        self._priv = Ed25519PrivateKey.generate()
        self._pub = self._priv.public_key()

    @property
    def public_key_b64(self) -> str:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        raw = self._pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.urlsafe_b64encode(raw).decode()

    def sign(self, data: bytes) -> str:
        sig = self._priv.sign(data)
        return base64.urlsafe_b64encode(sig).decode()


def _make_request_dict(pair: Ed25519Pair, **overrides) -> dict:
    """Build a ContactRequest dict and sign it correctly."""
    base: dict[str, Any] = {
        "request_id": str(uuid.uuid4()),
        "requester_did": "did:5h:alice",
        "requester_public_key_b64": pair.public_key_b64,
        "target_did": "did:5h:margaret",
        "hop_number": 1,
        "intent": {
            "intent_type": "professional_inquiry",
            "summary": "Test semantic verification",
            "anonymity_level": "identified",
        },
        "preferred_outcome": "forward",
        "consent_receipts": [],
        "encryption": "aes-256-gcm",
        "ttl_hops": 5,
    }
    base.update(overrides)

    # Sign over canonical input (spec/execution/canonical-serialization.md)
    signing_input = canonical_signing_input(base)
    base["signature"] = pair.sign(signing_input)
    return base


# ---------------------------------------------------------------------------
# RFC 8785 canonicalization tests
# ---------------------------------------------------------------------------

class TestCanonicalSigning:
    """Test vectors from spec/execution/canonical-serialization.md."""

    def test_keys_sorted_lexicographically(self):
        d = {"z_last": 1, "a_first": 2, "m_middle": {"z": 3, "a": 4}}
        # Remove signature (not present here, but test the function)
        without_sig = {k: v for k, v in d.items() if k != "signature"}
        canonical = json.dumps(without_sig, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        assert canonical == '{"a_first":2,"m_middle":{"a":4,"z":3},"z_last":1}'

    def test_no_whitespace(self):
        d = {"b": 2, "a": 1}
        canonical = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        assert " " not in canonical
        assert "\n" not in canonical

    def test_unicode_passthrough(self):
        d = {"summary": "Möte om 5H-protokollet"}
        canonical = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        assert canonical == '{"summary":"Möte om 5H-protokollet"}'

    def test_signature_field_excluded(self):
        d = {"a": 1, "signature": "should_be_removed", "b": 2}
        signing_input = canonical_signing_input(d)
        # Recompute without signature manually
        without_sig = {"a": 1, "b": 2}
        manual = json.dumps(without_sig, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        expected = hashlib.sha256(manual.encode("utf-8")).digest()
        assert signing_input == expected

    def test_deterministic_across_calls(self):
        d = {"b": 2, "a": 1, "signature": "x"}
        r1 = canonical_signing_input(d)
        r2 = canonical_signing_input(d)
        assert r1 == r2

    def test_different_content_different_hash(self):
        d1 = {"summary": "hello", "signature": "x"}
        d2 = {"summary": "world", "signature": "x"}
        assert canonical_signing_input(d1) != canonical_signing_input(d2)


# ---------------------------------------------------------------------------
# Semantic verification
# ---------------------------------------------------------------------------

class TestSemanticVerification:
    """Full Ed25519 verification against RFC 8785 canonical input."""

    def test_correct_signature_passes(self):
        pair = Ed25519Pair()
        req = _make_request_dict(pair)
        result = verify_request_signature(
            signature_str=req["signature"],
            requester_did=req["requester_did"],
            requester_public_key_b64=req["requester_public_key_b64"],
            request_dict=req,
        )
        assert result.ok
        assert result.semantic is True
        assert result.structural is True

    def test_tampered_summary_fails(self):
        pair = Ed25519Pair()
        req = _make_request_dict(pair)
        # Tamper with the request after signing
        req["intent"]["summary"] = "tampered content"
        result = verify_request_signature(
            signature_str=req["signature"],
            requester_did=req["requester_did"],
            requester_public_key_b64=req["requester_public_key_b64"],
            request_dict=req,
        )
        assert not result.ok
        assert result.semantic is False
        assert "RFC 8785" in result.detail

    def test_wrong_keypair_fails(self):
        pair1 = Ed25519Pair()
        pair2 = Ed25519Pair()
        req = _make_request_dict(pair1)
        # Pass pair2's public key — mismatch
        result = verify_request_signature(
            signature_str=req["signature"],
            requester_did=req["requester_did"],
            requester_public_key_b64=pair2.public_key_b64,
            request_dict=req,
        )
        assert not result.ok
        assert result.semantic is False

    def test_branch1_literal_signing_fails(self):
        """
        Documents that Branch 1's current b"full-flow-request" signing
        does NOT satisfy semantic verification. This is the v0.3 gap.
        """
        pair = Ed25519Pair()
        req = _make_request_dict(pair)
        # Override signature with Branch 1's current pattern
        branch1_sig = pair.sign(b"full-flow-request")  # type: ignore[arg-type]
        req["signature"] = branch1_sig

        result = verify_request_signature(
            signature_str=req["signature"],
            requester_did=req["requester_did"],
            requester_public_key_b64=pair.public_key_b64,
            request_dict=req,
        )
        # Structurally valid (real 64-byte sig), but semantically wrong
        assert result.structural is True
        assert result.semantic is False
        assert not result.ok

    def test_malformed_public_key_fails(self):
        pair = Ed25519Pair()
        req = _make_request_dict(pair)
        result = verify_request_signature(
            signature_str=req["signature"],
            requester_did=req["requester_did"],
            requester_public_key_b64="not_valid_base64!!!",
            request_dict=req,
        )
        assert not result.ok
        assert "valid" in result.detail.lower()

    def test_16_byte_key_fails(self):
        """Wrong key length: 16 bytes instead of 32."""
        pair = Ed25519Pair()
        req = _make_request_dict(pair)
        short_key = base64.urlsafe_b64encode(b"x" * 16).decode()
        result = verify_request_signature(
            signature_str=req["signature"],
            requester_did=req["requester_did"],
            requester_public_key_b64=short_key,
            request_dict=req,
        )
        assert not result.ok


# ---------------------------------------------------------------------------
# Enforcement mode
# ---------------------------------------------------------------------------

class TestEnforcementMode:
    """REQUIRE_SEMANTIC_VERIFICATION=true behaviour."""

    def test_enforcement_rejects_absent_key(self):
        """When enforcement is on, requests without a public key are rejected."""
        pair = Ed25519Pair()
        # Use a valid structural sig but no public key
        sig = pair.sign(b"anything")
        with unittest.mock.patch(
            "five_h_proxy.verification.REQUIRE_SEMANTIC_VERIFICATION", True
        ):
            result = verify_request_signature(
                signature_str=sig,
                requester_did="did:5h:alice",
                requester_public_key_b64=None,
                request_dict=None,
            )
        assert not result.ok
        assert result.structural is True
        assert result.semantic is False
        assert "REQUIRE_SEMANTIC_VERIFICATION=true" in result.detail
        assert "canonical-serialization.md" in result.detail

    def test_enforcement_passes_with_correct_key_and_sig(self):
        """Enforcement mode passes when key is present and sig is correct."""
        pair = Ed25519Pair()
        req = _make_request_dict(pair)
        with unittest.mock.patch(
            "five_h_proxy.verification.REQUIRE_SEMANTIC_VERIFICATION", True
        ):
            result = verify_request_signature(
                signature_str=req["signature"],
                requester_did=req["requester_did"],
                requester_public_key_b64=req["requester_public_key_b64"],
                request_dict=req,
            )
        assert result.ok
        assert result.semantic is True

    def test_compat_mode_accepts_absent_key(self):
        """v0.2 compat mode (enforcement=false) accepts absent key with warning."""
        pair = Ed25519Pair()
        sig = pair.sign(b"anything")
        with unittest.mock.patch(
            "five_h_proxy.verification.REQUIRE_SEMANTIC_VERIFICATION", False
        ):
            result = verify_request_signature(
                signature_str=sig,
                requester_did="did:5h:alice",
                requester_public_key_b64=None,
                request_dict=None,
            )
        assert result.ok
        assert result.semantic is None  # not attempted


# ---------------------------------------------------------------------------
# Integration: full forward() endpoint with semantic verification
# ---------------------------------------------------------------------------

class TestForwardEndpointSemantic:
    """Verify the forward() endpoint correctly routes to semantic verification."""

    def _client(self) -> TestClient:
        from five_h_proxy.proxy import app
        return TestClient(app)

    def test_request_with_correct_key_accepted(self):
        pair = Ed25519Pair()
        req = _make_request_dict(pair)
        resp = self._client().post("/v1/proxy/forward", json=req)
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] != ProxyDecision.REJECT.value

    def test_request_with_tampered_content_rejected(self):
        pair = Ed25519Pair()
        req = _make_request_dict(pair)
        req["intent"]["summary"] = "tampered after signing"
        resp = self._client().post("/v1/proxy/forward", json=req)
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == ProxyDecision.REJECT.value
        assert data["error"]["code"] == ErrorCode.POLICY_VIOLATION.value
        assert data["failure_class"] == FailureClass.HARD.value

    def test_branch1_literal_sig_structural_only_fallback(self):
        """
        Simulates Branch 1's current payload: requester_public_key_b64 absent,
        structural-only path. Should be accepted in compat mode.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv = Ed25519PrivateKey.generate()
        sig = base64.urlsafe_b64encode(priv.sign(b"full-flow-request")).decode()
        payload = {
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
            "signature": sig,
            "encryption": "aes-256-gcm",
            # NO requester_public_key_b64 — Branch 1 v0.2 shape
        }
        resp = self._client().post("/v1/proxy/forward", json=payload)
        assert resp.status_code == 200
        # Should be accepted (structural pass) in compat mode
        data = resp.json()
        assert data["decision"] != ProxyDecision.REJECT.value
