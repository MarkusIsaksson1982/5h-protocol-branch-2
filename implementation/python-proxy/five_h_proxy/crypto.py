"""
five_h_proxy/crypto.py

Real asymmetric cryptography for the reference server.

Generates an Ed25519 keypair at startup. The private key signs ConsentReceipt
action_hashes; the public key is exposed via /v1/proxy/health so clients can
verify receipts without trusting the server's self-report.

This is an ephemeral keypair (regenerated on restart). Production deployments
MUST load the private key from a persistent, hardware-backed key store (HSM,
cloud KMS, or at minimum an encrypted key file). The reference server is
intentionally simple here to avoid baking in a specific key-management pattern.

Fix for Gemini review critique C:
  Previously used sha256(data + key) — a symmetric MAC, not an asymmetric
  signature. This module replaces that with real Ed25519 across the codebase.

Authors: Claude (Anthropic)
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PublicFormat,
    PrivateFormat,
)
import base64


class ProxyKeyPair:
    """
    Ed25519 keypair for a single proxy instance.
    Instantiated once at module import; shared across all requests.
    """

    def __init__(self) -> None:
        self._private_key: Ed25519PrivateKey = Ed25519PrivateKey.generate()
        self._public_key: Ed25519PublicKey = self._private_key.public_key()

    def sign(self, data: str | bytes) -> str:
        """
        Sign data with the private key.
        Returns base64url-encoded signature string.
        """
        if isinstance(data, str):
            data = data.encode()
        raw_sig = self._private_key.sign(data)
        return base64.urlsafe_b64encode(raw_sig).decode()

    def verify(self, data: str | bytes, signature: str) -> bool:
        """
        Verify a base64url-encoded signature against data.
        Returns True if valid, False otherwise (never raises on bad sig).
        """
        if isinstance(data, str):
            data = data.encode()
        try:
            raw_sig = base64.urlsafe_b64decode(signature)
            self._public_key.verify(raw_sig, data)
            return True
        except Exception:
            return False

    @property
    def public_key_b64(self) -> str:
        """Base64url-encoded raw public key bytes (32 bytes for Ed25519)."""
        raw = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.urlsafe_b64encode(raw).decode()

    @property
    def public_key_hex(self) -> str:
        raw = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return raw.hex()


# Module-level singleton — one keypair per process lifetime.
# In production: replace with a key loaded from secure storage.
PROXY_KEYPAIR = ProxyKeyPair()
