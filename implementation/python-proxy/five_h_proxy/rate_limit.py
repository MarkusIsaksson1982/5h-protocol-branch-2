"""
five_h_proxy/rate_limit.py

Per-verification-tier sliding window rate limiter.

Fix applied (Gemini review 2026-04-12, critique A):
  Added purge_abandoned() to evict stale DID windows. Without this, any DID
  that makes exactly one request and never returns leaves a deque in _windows
  forever. The background sweeper in proxy.py calls this periodically.

Limits per hour:
  Level 0 (unverified):     5 requests
  Level 1 (social):       100 requests
  Level 2 (government): 1,000 requests

Authors: ChatGPT/Codex (OpenAI) – initial, Claude (Anthropic) – purge fix
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
    _windows: dict[str, deque[float]] = field(
        default_factory=lambda: defaultdict(deque)
    )

    def _key(self, did: str, level: VerificationLevel) -> str:
        return f"{did}:{level.value}"

    def check(self, did: str, level: VerificationLevel) -> tuple[bool, float | None]:
        """
        Returns (allowed, retry_after_seconds).
        retry_after_seconds is None when allowed=True.
        """
        now = time.monotonic()
        key = self._key(did, level)
        window = self._windows[key]
        limit = TIER_LIMITS[level]

        # Evict entries outside the window
        cutoff = now - WINDOW_SECONDS
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= limit:
            oldest = window[0]
            retry_after = WINDOW_SECONDS - (now - oldest)
            return False, retry_after

        window.append(now)
        return True, None

    def purge_abandoned(self) -> int:
        """
        Remove DID windows that are entirely outside the sliding window.
        Should be called by the background sweeper (not on the request path).

        Returns number of keys evicted.

        Fix A: without this, windows for DIDs that never return accumulate
        indefinitely. The eviction in check() only fires on new requests from
        the same DID — it cannot clean up truly abandoned keys.
        """
        now = time.monotonic()
        cutoff = now - WINDOW_SECONDS
        abandoned = [
            key for key, window in self._windows.items()
            if not window or window[-1] < cutoff
        ]
        for key in abandoned:
            del self._windows[key]
        return len(abandoned)
