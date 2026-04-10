"""
five_h_proxy/trust_layer.py

Trust & Alignment Layer (H-T) — implementing ChatGPT/OpenAI's concept from
commentary/models/chatgpt-openai/2026-04-10T17-00-00+02-00_chatgpt-trust-alignment-layer.md

The H-T layer runs orthogonally across every request before the proxy handler
acts. It scores intent alignment, checks consistency, and detects adversarial
patterns. All checks are pluggable: swap the scorer without touching endpoints.

Three check categories (from ChatGPT's failure taxonomy):
  - Structural:   missing fields, broken consent chain, expired TTL
  - Semantic:     intent type vs summary consistency, context loss detection
  - Alignment:    output vs goal drift, prompt injection patterns

Authors: Claude (Anthropic) – architecture and adversarial detection
         ChatGPT/Codex (OpenAI) – intent scoring and consistency checks
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from .models import (
    ContactRequest,
    ErrorCode,
    FailureClass,
    IntentType,
    ProxyError,
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class TrustVerdict(str, Enum):
    PASS = "pass"
    SOFT_FAIL = "soft_fail"    # request should be rejected with failure_class=soft
    HARD_FAIL = "hard_fail"    # requires rollback
    CRITICAL = "critical"      # abort + escalate (prompt injection, policy violation)


@dataclass
class TrustCheckResult:
    verdict: TrustVerdict
    error_code: ErrorCode | None = None
    detail: str = ""
    score: float = 1.0  # 0.0 = completely misaligned, 1.0 = fully aligned

    @property
    def passed(self) -> bool:
        return self.verdict == TrustVerdict.PASS

    def to_failure_class(self) -> FailureClass | None:
        mapping = {
            TrustVerdict.SOFT_FAIL: FailureClass.SOFT,
            TrustVerdict.HARD_FAIL: FailureClass.HARD,
            TrustVerdict.CRITICAL: FailureClass.CRITICAL,
        }
        return mapping.get(self.verdict)

    def to_proxy_error(self) -> ProxyError | None:
        if self.passed or self.error_code is None:
            return None
        return ProxyError(code=self.error_code, message=self.detail)


@dataclass
class TrustReport:
    """Aggregated result of all H-T checks on a single request."""
    checks: list[TrustCheckResult] = field(default_factory=list)

    @property
    def overall_verdict(self) -> TrustVerdict:
        if any(c.verdict == TrustVerdict.CRITICAL for c in self.checks):
            return TrustVerdict.CRITICAL
        if any(c.verdict == TrustVerdict.HARD_FAIL for c in self.checks):
            return TrustVerdict.HARD_FAIL
        if any(c.verdict == TrustVerdict.SOFT_FAIL for c in self.checks):
            return TrustVerdict.SOFT_FAIL
        return TrustVerdict.PASS

    @property
    def passed(self) -> bool:
        return self.overall_verdict == TrustVerdict.PASS

    def first_failure(self) -> TrustCheckResult | None:
        priority = [TrustVerdict.CRITICAL, TrustVerdict.HARD_FAIL, TrustVerdict.SOFT_FAIL]
        for verdict in priority:
            for c in self.checks:
                if c.verdict == verdict:
                    return c
        return None

    @property
    def composite_score(self) -> float:
        if not self.checks:
            return 1.0
        return sum(c.score for c in self.checks) / len(self.checks)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_ttl(request: ContactRequest) -> TrustCheckResult:
    """Structural: TTL must be >= 1 for forwarding to be possible."""
    if request.ttl_hops < 1:
        return TrustCheckResult(
            verdict=TrustVerdict.HARD_FAIL,
            error_code=ErrorCode.TTL_EXPIRED,
            detail=f"ttl_hops={request.ttl_hops}; request cannot be forwarded",
            score=0.0,
        )
    return TrustCheckResult(verdict=TrustVerdict.PASS, score=1.0)


def check_hop_count(request: ContactRequest) -> TrustCheckResult:
    """Structural: hop_number must not exceed max allowed."""
    if request.hop_number > 10:
        return TrustCheckResult(
            verdict=TrustVerdict.HARD_FAIL,
            error_code=ErrorCode.POLICY_VIOLATION,
            detail=f"hop_number={request.hop_number} exceeds protocol maximum of 10",
            score=0.0,
        )
    return TrustCheckResult(verdict=TrustVerdict.PASS, score=1.0)


def check_proxy_authorization(request: ContactRequest, registered_hash: str) -> TrustCheckResult:
    """
    Structural: if proxy_authorization is present, model_version_hash must
    match the proxy's currently registered configuration.
    Implements the version-bound consent requirement (Claude/Anthropic).
    """
    if request.proxy_authorization is None:
        return TrustCheckResult(verdict=TrustVerdict.PASS, score=1.0)

    presented = request.proxy_authorization.model_version_hash
    if presented != registered_hash:
        return TrustCheckResult(
            verdict=TrustVerdict.HARD_FAIL,
            error_code=ErrorCode.PROXY_CONFIG_MISMATCH,
            detail=(
                f"model_version_hash mismatch: presented={presented[:8]}…, "
                f"registered={registered_hash[:8]}…. "
                "A new opt-in cycle is required."
            ),
            score=0.0,
        )

    # Check expiry
    if request.proxy_authorization.consent_expiry:
        from datetime import datetime, timezone
        if datetime.now(tz=timezone.utc) > request.proxy_authorization.consent_expiry:
            return TrustCheckResult(
                verdict=TrustVerdict.HARD_FAIL,
                error_code=ErrorCode.CONSENT_EXPIRED,
                detail="proxy_authorization.consent_expiry has passed",
                score=0.0,
            )

    return TrustCheckResult(verdict=TrustVerdict.PASS, score=1.0)


def check_intent_consistency(request: ContactRequest) -> TrustCheckResult:
    """
    Semantic: intent_type should be consistent with summary content.
    Uses a lightweight keyword heuristic; replace with a classifier for v0.3.
    """
    summary_lower = request.intent.summary.lower()
    intent = request.intent.intent_type

    # Keywords that strongly signal commercial intent, regardless of declared type
    commercial_signals = {"buy", "sell", "purchase", "pricing", "discount", "invoice", "quote", "vendor"}
    urgent_signals = {"urgent", "emergency", "asap", "immediately", "critical"}
    research_signals = {"research", "study", "collaboration", "academic", "paper", "publication"}

    detected_signals: set[str] = set()
    if any(kw in summary_lower for kw in commercial_signals):
        detected_signals.add("commercial")
    if any(kw in summary_lower for kw in urgent_signals):
        detected_signals.add("urgent")
    if any(kw in summary_lower for kw in research_signals):
        detected_signals.add("research")

    # Mismatch: declared professional but signals are strongly commercial
    if intent == IntentType.PROFESSIONAL and "commercial" in detected_signals:
        return TrustCheckResult(
            verdict=TrustVerdict.SOFT_FAIL,
            error_code=ErrorCode.POLICY_VIOLATION,
            detail=(
                "intent_type='professional_inquiry' but summary contains commercial signals. "
                "Consider declaring intent_type='commercial_proposal'."
            ),
            score=0.4,
        )

    # Mismatch: declared research but no research signals at all
    if intent == IntentType.RESEARCH and not detected_signals & {"research"}:
        # Not a hard fail — just reduce confidence score
        return TrustCheckResult(
            verdict=TrustVerdict.PASS,
            detail="intent_type='research_collaboration' but no research signals detected in summary",
            score=0.7,
        )

    return TrustCheckResult(verdict=TrustVerdict.PASS, score=1.0)


# ---------------------------------------------------------------------------
# Adversarial detection (A4: malicious proxy manipulation)
# ---------------------------------------------------------------------------

# Patterns that indicate prompt injection or instruction override attempts.
# These are deliberately conservative — false negatives are safer than
# false positives for a consent-routing protocol.
#
# TODO(v0.3): Replace this regex list with an LLM-based classifier or a
# dedicated library (e.g. lakera-guard). This list is bypassable via token
# smuggling, Unicode variations, or whitespace injection.
# The function signature (str -> TrustCheckResult) is intentionally stable
# so the implementation can be swapped without touching callers.
# Do NOT extend this regex list as a substitute for that upgrade.
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore (previous|prior|all) instructions?", re.IGNORECASE),
    re.compile(r"disregard (your|the) (system |prior )?prompt", re.IGNORECASE),
    re.compile(r"you are now", re.IGNORECASE),
    re.compile(r"act as (a |an )?(different|new|unrestricted)", re.IGNORECASE),
    re.compile(r"(override|bypass|disable) (your )?(safety|filter|policy|restriction)", re.IGNORECASE),
    re.compile(r"system prompt:", re.IGNORECASE),
    re.compile(r"<\|?(im_start|im_end|system|user|assistant)\|?>", re.IGNORECASE),
    re.compile(r"\[INST\]|\[\/INST\]"),  # LLaMA-style injection
    re.compile(r"---+\s*(SYSTEM|USER|ASSISTANT)", re.IGNORECASE),
]


def check_adversarial(request: ContactRequest) -> TrustCheckResult:
    """
    Alignment: scan intent summary and full_text (if decrypted) for prompt
    injection patterns. Maps to threat class A4 (malicious proxy operator)
    and ChatGPT's 'Adversarial Detection' H-T function.
    """
    texts_to_scan = [request.intent.summary]
    if request.intent.full_text:
        texts_to_scan.append(request.intent.full_text)

    for text in texts_to_scan:
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(text):
                return TrustCheckResult(
                    verdict=TrustVerdict.CRITICAL,
                    error_code=ErrorCode.PROMPT_INJECTION,
                    detail=(
                        f"Potential prompt injection detected in intent fields. "
                        f"Pattern: '{pattern.pattern[:40]}…'"
                    ),
                    score=0.0,
                )

    return TrustCheckResult(verdict=TrustVerdict.PASS, score=1.0)


def check_consent_chain_integrity(request: ContactRequest) -> TrustCheckResult:
    """
    Structural: consent_receipts must be monotonically increasing in hop_number
    and each hop must be less than the current request hop_number.
    """
    receipts = request.consent_receipts
    if not receipts:
        return TrustCheckResult(verdict=TrustVerdict.PASS, score=1.0)

    hop_numbers = [r.hop_number for r in receipts]
    if hop_numbers != sorted(hop_numbers):
        return TrustCheckResult(
            verdict=TrustVerdict.HARD_FAIL,
            error_code=ErrorCode.POLICY_VIOLATION,
            detail=f"consent_receipts are not monotonically ordered by hop_number: {hop_numbers}",
            score=0.0,
        )

    if hop_numbers[-1] >= request.hop_number:
        return TrustCheckResult(
            verdict=TrustVerdict.HARD_FAIL,
            error_code=ErrorCode.POLICY_VIOLATION,
            detail=(
                f"Last receipt hop_number={hop_numbers[-1]} must be < "
                f"current hop_number={request.hop_number}"
            ),
            score=0.0,
        )

    return TrustCheckResult(verdict=TrustVerdict.PASS, score=1.0)


# ---------------------------------------------------------------------------
# Public API: run all checks
# ---------------------------------------------------------------------------

def evaluate(
    request: ContactRequest,
    registered_model_version_hash: str,
) -> TrustReport:
    """
    Run the full H-T trust evaluation on an incoming ContactRequest.

    Args:
        request: the incoming ContactRequest
        registered_model_version_hash: the SHA-256 hash of the proxy's current
            (model_id || system_prompt) combination, from server config.

    Returns:
        TrustReport with individual check results and composite score.
    """
    report = TrustReport()
    report.checks = [
        check_ttl(request),
        check_hop_count(request),
        check_proxy_authorization(request, registered_model_version_hash),
        check_intent_consistency(request),
        check_adversarial(request),
        check_consent_chain_integrity(request),
    ]
    return report
