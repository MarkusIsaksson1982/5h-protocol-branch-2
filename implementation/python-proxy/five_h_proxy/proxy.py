"""
five_h_proxy/proxy.py

5H Protocol – Python AI Proxy Reference Server

Implements all four required endpoints from spec/schemas/ai-proxy.json:
  POST /v1/proxy/forward
  POST /v1/proxy/redact/{request_id}
  GET  /v1/proxy/escrow/{token}/approve  (query param: approver_did)
  GET  /v1/proxy/escrow/{token}/release
  GET  /v1/proxy/health

FastAPI generates /openapi.json automatically from these definitions.
That JSON is the basis for spec/openapi/proxy-api.yaml.

Authors: Claude (Anthropic) – architecture, consent chain, trust integration
         ChatGPT/Codex (OpenAI) – endpoint implementation and escrow flow
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from .models import (
    AnonymityLevel,
    ContactRequest,
    ConsentReceipt,
    ErrorCode,
    FailureClass,
    HealthResponse,
    IntentType,
    ProxyDecision,
    ProxyError,
    ProxyResponse,
    ReceiptMode,
    RedactionProof,
    RedactionRequest,
    VerificationLevel,
)
from .consent import ReceiptStore, make_receipt
from .rate_limit_and_escrow import EscrowStore, RateLimiter
from .trust_layer import TrustVerdict, evaluate as trust_evaluate


# ---------------------------------------------------------------------------
# Server configuration
# ---------------------------------------------------------------------------

# In production, load from environment or a signed config file.
# The model_version_hash commits to (model_id || system_prompt).
PROXY_DID = os.getenv("PROXY_DID", "did:5h:proxy-branch2-ref")
MODEL_ID = os.getenv("PROXY_MODEL_ID", "claude-sonnet-4-20250514")
SYSTEM_PROMPT = os.getenv(
    "PROXY_SYSTEM_PROMPT",
    "Forward professional inquiries. Summarize commercial proposals. Reject spam.",
)

def _compute_model_version_hash(model_id: str, system_prompt: str) -> str:
    return hashlib.sha256(f"{model_id}||{system_prompt}".encode()).hexdigest()

MODEL_VERSION_HASH = _compute_model_version_hash(MODEL_ID, SYSTEM_PROMPT)

RECEIPT_STORE = ReceiptStore(Path(os.getenv("RECEIPT_STORE_DIR", "/tmp/5h_receipts")))
ESCROW_STORE = EscrowStore()
RATE_LIMITER = RateLimiter()

# Default receipt mode for this proxy instance (operators may override)
DEFAULT_RECEIPT_MODE = ReceiptMode(os.getenv("RECEIPT_MODE", ReceiptMode.FULL_CHAIN.value))


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="5H Protocol – AI Proxy Reference Server",
    description=(
        "Reference implementation of the 5H Protocol AI Proxy Wire Protocol "
        "(spec/schemas/ai-proxy.json). Implements all four required endpoints. "
        "See /openapi.json for the machine-readable API contract."
    ),
    version="0.2.0",
    contact={"name": "Claude, Anthropic (branch-2 lead)"},
    license_info={"name": "MIT OR Apache-2.0"},
)


# ---------------------------------------------------------------------------
# Helper: rejection response
# ---------------------------------------------------------------------------

def _reject(
    request_id: uuid.UUID,
    hop_number: int,
    error_code: ErrorCode,
    message: str,
    failure_class: FailureClass,
) -> ProxyResponse:
    receipt = make_receipt(
        request_id=request_id,
        hop_number=hop_number,
        proxy_did=PROXY_DID,
        decision=ProxyDecision.REJECT.value,
        prior_receipts=[],
        receipt_mode=DEFAULT_RECEIPT_MODE,
        model_version_hash=MODEL_VERSION_HASH,
    )
    return ProxyResponse(
        request_id=request_id,
        decision=ProxyDecision.REJECT,
        failure_class=failure_class,
        consent_receipt=receipt,
        error=ProxyError(code=error_code, message=message),
    )


# ---------------------------------------------------------------------------
# Summarizer (pluggable)
# ---------------------------------------------------------------------------

def _summarize(intent_summary: str) -> str:
    """
    Default identity summarizer — returns the summary unchanged.
    Replace with a model call for production.

    The trait boundary (str → str) is what matters; the model is pluggable.
    ChatGPT's PES deterministic envelope: T(Hn) applied here.
    """
    return intent_summary


# ---------------------------------------------------------------------------
# Endpoint: POST /v1/proxy/forward
# ---------------------------------------------------------------------------

@app.post(
    "/v1/proxy/forward",
    response_model=ProxyResponse,
    summary="Forward a ContactRequest along the consent chain",
    description=(
        "Primary endpoint. Receives a signed, encrypted ContactRequest. "
        "Runs H-T trust evaluation, rate limiting, and policy checks before "
        "deciding: forward | summarize | escrow | reject | accept-and-connect."
    ),
)
async def forward(request: ContactRequest) -> ProxyResponse:
    # 1. H-T Trust Layer evaluation (ChatGPT's H-T concept, implemented)
    trust_report = trust_evaluate(request, MODEL_VERSION_HASH)
    if not trust_report.passed:
        failure = trust_report.first_failure()
        assert failure is not None
        fc = failure.to_failure_class() or FailureClass.SOFT
        return _reject(
            request_id=request.request_id,
            hop_number=request.hop_number,
            error_code=failure.error_code or ErrorCode.POLICY_VIOLATION,
            message=failure.detail,
            failure_class=fc,
        )

    # 2. Rate limiting by verification tier
    # In a real deployment, the verification level comes from the graph store
    # lookup of requester_did. Here we default to Level 0 for unknown DIDs
    # (conservative; real impl calls graph engine).
    requester_level = VerificationLevel.UNVERIFIED
    allowed, retry_after = RATE_LIMITER.check(str(request.requester_did), requester_level)
    if not allowed:
        from datetime import timedelta
        retry_dt = datetime.now(tz=timezone.utc) + timedelta(seconds=retry_after or 3600)
        receipt = make_receipt(
            request_id=request.request_id,
            hop_number=request.hop_number,
            proxy_did=PROXY_DID,
            decision=ProxyDecision.REJECT.value,
            prior_receipts=request.consent_receipts,
            receipt_mode=DEFAULT_RECEIPT_MODE,
            model_version_hash=MODEL_VERSION_HASH,
        )
        return ProxyResponse(
            request_id=request.request_id,
            decision=ProxyDecision.REJECT,
            failure_class=FailureClass.SOFT,
            consent_receipt=receipt,
            error=ProxyError(
                code=ErrorCode.RATE_LIMIT,
                message=f"Rate limit exceeded for verification level {requester_level.name}",
                rate_limit_retry_after=retry_dt,
            ),
        )

    # 3. Decrement TTL
    remaining_ttl = request.ttl_hops - 1

    # 4. Routing decision based on preferred_outcome and policy
    #
    # Policy for this reference proxy:
    #   - commercial_proposal → escrow (unless requester is Level-2)
    #   - urgent_contact → forward immediately
    #   - everything else → summarize then forward
    #
    # Override with preferred_outcome when consistent with policy.

    intent_type = request.intent.intent_type
    preferred = request.preferred_outcome

    from .models import PreferredOutcome
    if intent_type == IntentType.COMMERCIAL and requester_level < VerificationLevel.GOVERNMENT:
        decision = ProxyDecision.ESCROW
    elif preferred == PreferredOutcome.ESCROW:
        decision = ProxyDecision.ESCROW
    elif preferred == PreferredOutcome.CONNECT:
        decision = ProxyDecision.ACCEPT_AND_CONNECT
    elif preferred == PreferredOutcome.FORWARD and remaining_ttl > 0:
        decision = ProxyDecision.FORWARD
    else:
        decision = ProxyDecision.SUMMARIZE

    # 5. Build consent receipt for this hop
    prior = request.consent_receipts
    receipt = make_receipt(
        request_id=request.request_id,
        hop_number=request.hop_number,
        proxy_did=PROXY_DID,
        decision=decision.value,
        prior_receipts=prior,
        receipt_mode=DEFAULT_RECEIPT_MODE,
        model_version_hash=MODEL_VERSION_HASH,
    )
    RECEIPT_STORE.append(str(request.request_id), receipt)

    # 6. Execute decision
    if decision == ProxyDecision.ESCROW:
        ciphertext = (request.intent.full_text or "").encode()
        token = ESCROW_STORE.create(
            request_id=str(request.request_id),
            requester_did=str(request.requester_did),
            target_did=str(request.target_did),
            ciphertext=ciphertext,
        )
        return ProxyResponse(
            request_id=request.request_id,
            decision=ProxyDecision.ESCROW,
            escrow_token=token,
            consent_receipt=receipt,
        )

    elif decision == ProxyDecision.SUMMARIZE:
        summary = _summarize(request.intent.summary)
        return ProxyResponse(
            request_id=request.request_id,
            decision=ProxyDecision.SUMMARIZE,
            summary=summary,
            next_hop_did=request.target_did,
            consent_receipt=receipt,
        )

    elif decision == ProxyDecision.FORWARD:
        return ProxyResponse(
            request_id=request.request_id,
            decision=ProxyDecision.FORWARD,
            next_hop_did=request.target_did,
            consent_receipt=receipt,
        )

    else:  # ACCEPT_AND_CONNECT
        return ProxyResponse(
            request_id=request.request_id,
            decision=ProxyDecision.ACCEPT_AND_CONNECT,
            consent_receipt=receipt,
        )


# ---------------------------------------------------------------------------
# Endpoint: POST /v1/proxy/redact/{request_id}
# ---------------------------------------------------------------------------

@app.post(
    "/v1/proxy/redact/{request_id}",
    response_model=RedactionProof,
    summary="Delete local logs for a request (right-to-be-forgotten)",
)
async def redact(request_id: str, body: RedactionRequest) -> RedactionProof:
    if str(body.request_id) != request_id:
        raise HTTPException(400, "request_id in path and body must match")

    # In production: verify body.signature against requester's registered public key.
    # Synthetic verification for reference implementation.

    deletion_hash = RECEIPT_STORE.delete(request_id)
    now = datetime.now(tz=timezone.utc)

    # Tombstone signature: in production sign over deletion_hash with proxy key
    proxy_signature = hashlib.sha256(f"DELETED:{deletion_hash}:{PROXY_DID}".encode()).hexdigest()

    return RedactionProof(
        request_id=body.request_id,
        deletion_timestamp=now,
        deletion_hash=deletion_hash,
        proxy_signature=proxy_signature,
    )


# ---------------------------------------------------------------------------
# Endpoint: GET /v1/proxy/escrow/{token}/approve
# ---------------------------------------------------------------------------

@app.get(
    "/v1/proxy/escrow/{token}/approve",
    summary="Approve escrow release (requester or target)",
)
async def approve_escrow(
    token: str,
    approver_did: str = Query(..., description="DID of the approving party"),
    signature: str = Query(..., description="Approver's signature over the token"),
) -> JSONResponse:
    # In production: verify signature against approver_did's registered public key
    success, message = ESCROW_STORE.approve(token, approver_did)
    if not success:
        raise HTTPException(400, message)
    return JSONResponse({"status": "approved", "message": message})


# ---------------------------------------------------------------------------
# Endpoint: GET /v1/proxy/escrow/{token}/release
# ---------------------------------------------------------------------------

@app.get(
    "/v1/proxy/escrow/{token}/release",
    summary="Release escrowed payload after dual approval",
)
async def release_escrow(token: str) -> JSONResponse:
    ciphertext, message = ESCROW_STORE.release(token)
    if ciphertext is None:
        raise HTTPException(403, message)
    return JSONResponse({
        "status": "released",
        "ciphertext_b64": ciphertext.decode(errors="replace"),
        "message": message,
    })


# ---------------------------------------------------------------------------
# Endpoint: GET /v1/proxy/health
# ---------------------------------------------------------------------------

@app.get(
    "/v1/proxy/health",
    response_model=HealthResponse,
    summary="Proxy liveness and current model_version_hash",
    description=(
        "Returns the proxy's current model_version_hash so clients can verify "
        "that the proxy configuration matches what they consented to."
    ),
)
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        model_version_hash=MODEL_VERSION_HASH,
        schema_version="0.2.0-draft",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run() -> None:
    uvicorn.run("five_h_proxy.proxy:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    run()
