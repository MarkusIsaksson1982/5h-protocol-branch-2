"""
five_h_proxy/escrow.py

Escrow store: holds encrypted payloads pending dual approval.

Fix applied (Gemini review 2026-04-12, critique A):
  purge_expired() existed but was never called. It is now called by the
  background sweeper registered in proxy.py's lifespan handler, so expired
  entries are evicted even if neither party ever returns to release/cancel.

Protocol:
  1. On decision='escrow', store sha256(full_text_encrypted) + ciphertext
     under a random opaque token. Return the token.
  2. Requester and target each approve via GET /v1/proxy/escrow/{token}/approve.
  3. When both have approved, GET /v1/proxy/escrow/{token}/release returns
     the original ciphertext.
  4. TTL: entries auto-expire after 7 days.

Authors: ChatGPT/Codex (OpenAI) – initial, Claude (Anthropic) – dual-consent logic
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field


ESCROW_TTL_SECONDS = 7 * 24 * 3600  # 7 days


@dataclass
class EscrowEntry:
    token: str
    request_id: str
    requester_did: str
    target_did: str
    payload_hash: str
    ciphertext: bytes
    created_at: float = field(default_factory=time.monotonic)
    requester_approved: bool = False
    target_approved: bool = False

    @property
    def is_expired(self) -> bool:
        return time.monotonic() - self.created_at > ESCROW_TTL_SECONDS

    @property
    def dual_approved(self) -> bool:
        return self.requester_approved and self.target_approved


class EscrowStore:
    def __init__(self) -> None:
        self._entries: dict[str, EscrowEntry] = {}

    def create(
        self,
        request_id: str,
        requester_did: str,
        target_did: str,
        ciphertext: bytes,
    ) -> str:
        token = secrets.token_urlsafe(32)
        payload_hash = hashlib.sha256(ciphertext).hexdigest()
        self._entries[token] = EscrowEntry(
            token=token,
            request_id=request_id,
            requester_did=requester_did,
            target_did=target_did,
            payload_hash=payload_hash,
            ciphertext=ciphertext,
        )
        return token

    def approve(self, token: str, approver_did: str) -> tuple[bool, str]:
        entry = self._entries.get(token)
        if entry is None:
            return False, "escrow token not found"
        if entry.is_expired:
            del self._entries[token]
            return False, "escrow entry has expired"
        if approver_did == entry.requester_did:
            entry.requester_approved = True
        elif approver_did == entry.target_did:
            entry.target_approved = True
        else:
            return False, f"approver_did is not a party to this escrow"
        return True, "approved"

    def release(self, token: str) -> tuple[bytes | None, str]:
        entry = self._entries.get(token)
        if entry is None:
            return None, "escrow token not found"
        if entry.is_expired:
            del self._entries[token]
            return None, "escrow entry has expired"
        if not entry.dual_approved:
            missing = []
            if not entry.requester_approved:
                missing.append("requester")
            if not entry.target_approved:
                missing.append("target")
            return None, f"awaiting approval from: {', '.join(missing)}"
        ciphertext = entry.ciphertext
        del self._entries[token]
        return ciphertext, "released"

    def purge_expired(self) -> int:
        """
        Evict all expired entries. Called by the background sweeper in proxy.py.

        Fix A: previously this method existed but was never invoked, so expired
        entries accumulated until process restart.
        """
        expired = [t for t, e in self._entries.items() if e.is_expired]
        for t in expired:
            del self._entries[t]
        return len(expired)
