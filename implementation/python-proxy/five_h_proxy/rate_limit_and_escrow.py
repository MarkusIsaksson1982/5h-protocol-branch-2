"""
five_h_proxy/rate_limit.py

Per-verification-tier sliding window rate limiter.

Limits per hour (configurable):
  Level 0 (unverified):  5 requests
  Level 1 (social):     100 requests
  Level 2 (government): 1000 requests

Returns failure_class='soft' when exceeded (per spec).

Authors: ChatGPT/Codex (OpenAI), Claude (Anthropic) – tier policy
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .models import VerificationLevel


TIER_LIMITS: dict[VerificationLevel, int] = {
    VerificationLevel.UNVERIFIED: 5,
    VerificationLevel.SOCIAL: 100,
    VerificationLevel.GOVERNMENT: 1000,
}

WINDOW_SECONDS = 3600  # 1 hour


@dataclass
class RateLimiter:
    _windows: dict[str, deque[float]] = field(default_factory=lambda: defaultdict(deque))

    def _key(self, did: str, level: VerificationLevel) -> str:
        return f"{did}:{level.value}"

    def check(self, did: str, level: VerificationLevel) -> tuple[bool, float | None]:
        """
        Returns (allowed: bool, retry_after_seconds: float | None).
        retry_after_seconds is None when allowed=True.
        """
        now = time.monotonic()
        key = self._key(did, level)
        window = self._windows[key]
        limit = TIER_LIMITS[level]

        # Evict entries older than the window
        cutoff = now - WINDOW_SECONDS
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= limit:
            oldest = window[0]
            retry_after = WINDOW_SECONDS - (now - oldest)
            return False, retry_after

        window.append(now)
        return True, None


"""
five_h_proxy/escrow.py

Escrow store: holds encrypted payloads pending dual approval.

Protocol:
  1. On decision='escrow', store sha256(full_text_encrypted) + ciphertext
     under a random opaque token. Return the token.
  2. Requester and target each POST /v1/proxy/escrow/{token}/approve
     with their DID + signature.
  3. When both have approved, /v1/proxy/escrow/{token}/release returns
     the original ciphertext.
  4. TTL: payloads auto-expire after 7 days (configurable).

Authors: ChatGPT/Codex (OpenAI) – implementation
         Claude (Anthropic) – dual-consent logic
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
        """
        Returns (success, message).
        approver_did is matched against requester_did or target_did.
        """
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
            return False, f"approver_did={approver_did!r} is not a party to this escrow"

        return True, "approved"

    def release(self, token: str) -> tuple[bytes | None, str]:
        """
        Returns (ciphertext, message).
        ciphertext is None when dual approval is not yet met or token invalid.
        """
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
        expired = [t for t, e in self._entries.items() if e.is_expired]
        for t in expired:
            del self._entries[t]
        return len(expired)
