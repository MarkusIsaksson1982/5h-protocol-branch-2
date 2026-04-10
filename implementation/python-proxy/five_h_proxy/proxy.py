"""
five_h_proxy/proxy.py

5H Protocol – Python AI Proxy Reference Server

Fixes applied (Gemini review 2026-04-12):
  A. Background lifespan sweeper calls EscrowStore.purge_expired() and
     RateLimiter.purge_abandoned() every 60 seconds.
  C. /v1/proxy/health now exposes the real Ed25519 public key so clients
     can verify ConsentReceipt signatures without trusting the server's
     self-report.
  All async file I/O changes are in consent.py (ReceiptStore.append is now
  awaited correctly here).

Endpoints (unchanged from original):
  POST /v1/proxy/forward
  POST /v1/proxy/redact/{request_id}
  GET  /v1/proxy/escrow/{token}/approve
  GET  /v1/proxy/escrow/{token}/release
  GET  /v1/proxy/health

Authors: Claude (Anthropic) – architecture, consent chain, trust integration
         ChatGPT/Codex (OpenAI) – endpoint implementation and escrow flow
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from .consent import ReceiptStore, make_receipt
from .crypto import PROXY_KEYPAIR
from .escrow import EscrowStore
from .models import (
    AnonymityLevel,
    ContactRequest,
    ConsentReceipt,
    ErrorCode,
    FailureClass,
    HealthResponse,
    IntentType,
    PreferredOutcome,
    ProxyDecision,
    ProxyError,
    ProxyResponse,
    ReceiptMode,
    RedactionProof,
    RedactionRequest,
    VerificationLevel,
)
from .rate_limit import RateLimiter
from .trust_layer import TrustVerdict, evaluate as trust_evaluate


# ---------------------------------------------------------------------------
# Server configuration
# ---------------------------------------------------------------------------

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
DEFAULT_RECEIPT_MODE = ReceiptMode(os.getenv("RECEIPT_MODE", ReceiptMode.FULL_CHAIN.value))

SWEEP_INTERVAL_SECONDS = int(os.getenv("SWEEP_INTERVAL", "60"))


# ---------------------------------------------------------------------------
# Lifespan: background sweeper (fix A)
# ---------------------------------------------------------------------------

async def _background_sweeper() -> None:
    """
    Periodically evict stale entries from in-memory stores.

    Without this, both RateLimiter and EscrowStore accumulate entries for
    DIDs/tokens that never return. The sweeper runs every SWEEP_INTERVAL_SECONDS
    and is intentionally off the request path.
    """
    while True:
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
        evicted_rate = RATE_LIMITER.purge_abandoned()
        evicted_escrow = ESCROW_STORE.purge_expired()
        if evicted_rate or evicted_escrow:
            # In production: emit to structured logging / metrics
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_background_sweeper())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="5H Protocol – AI Proxy Reference Server",
    description=(
        "Reference implementation of the 5H Protocol AI Proxy Wire Protocol "
        "(spec/schemas/ai-proxy.json). All four required endpoints implemented. "
        "See /openapi.json for the machine-readable API contract."
    ),
    version="0.2.1",
    contact={"name": "Claude, Anthropic (branch-2 lead)"},
    license_info={"name": "MIT OR Apache-2.0"},
    lifespan=lifespan,
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
    prior_receipts: list[ConsentReceipt] | None = None,
) -> ProxyResponse:
    receipt = make_receipt(
        request_id=request_id,
        hop_number=hop_number,
        proxy_did=PROXY_DID,
        decision=ProxyDecision.REJECT.value,
        prior_receipts=prior_receipts or [],
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
# Summarizer (pluggable — swap for model call in production)
# ---------------------------------------------------------------------------

def _summarize(intent_summary: str) -> str:
    """
    Default identity summarizer. The function boundary is what matters;
    replace the body with a model API call for production deployments.
    """
    return intent_summary


# ---------------------------------------------------------------------------
# Endpoint: POST /v1/proxy/forward
# ---------------------------------------------------------------------------

@app.post("/v1/proxy/forward", response_model=ProxyResponse)
async def forward(request: ContactRequest) -> ProxyResponse:
    # 1. H-T Trust Layer
    trust_report = trust_evaluate(request, MODEL_VERSION_HASH)
    if not trust_report.passed:
        failure = trust_report.first_failure()
        assert failure is not None
        return _reject(
            request_id=request.request_id,
            hop_number=request.hop_number,
            error_code=failure.error_code or ErrorCode.POLICY_VIOLATION,
            message=failure.detail,
            failure_class=failure.to_failure_class() or FailureClass.SOFT,
            prior_receipts=request.consent_receipts,
        )

    # 2. Rate limiting (defaults to UNVERIFIED; wire to graph engine for real level)
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
                message=f"Rate limit exceeded for tier {requester_level.name}",
                rate_limit_retry_after=retry_dt,
            ),
        )

    # 3. Routing decision
    remaining_ttl = request.ttl_hops - 1
    intent_type = request.intent.intent_type
    preferred = request.preferred_outcome

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

    # 4. Build and persist receipt (now async)
    receipt = make_receipt(
        request_id=request.request_id,
        hop_number=request.hop_number,
        proxy_did=PROXY_DID,
        decision=decision.value,
        prior_receipts=request.consent_receipts,
        receipt_mode=DEFAULT_RECEIPT_MODE,
        model_version_hash=MODEL_VERSION_HASH,
    )
    await RECEIPT_STORE.append(str(request.request_id), receipt)

    # 5. Execute decision
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
        return ProxyResponse(
            request_id=request.request_id,
            decision=ProxyDecision.SUMMARIZE,
            summary=_summarize(request.intent.summary),
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

@app.post("/v1/proxy/redact/{request_id}", response_model=RedactionProof)
async def redact(request_id: str, body: RedactionRequest) -> RedactionProof:
    if str(body.request_id) != request_id:
        raise HTTPException(400, "request_id in path and body must match")

    # Streaming delete (fix D is in consent.py; this await is correct)
    deletion_hash = await RECEIPT_STORE.delete(request_id)
    now = datetime.now(tz=timezone.utc)

    # Real Ed25519 signature over tombstone (fix C)
    proxy_signature = PROXY_KEYPAIR.sign(f"DELETED:{deletion_hash}:{PROXY_DID}")

    return RedactionProof(
        request_id=body.request_id,
        deletion_timestamp=now,
        deletion_hash=deletion_hash,
        proxy_signature=proxy_signature,
    )


# ---------------------------------------------------------------------------
# Endpoint: GET /v1/proxy/escrow/{token}/approve
# ---------------------------------------------------------------------------

@app.get("/v1/proxy/escrow/{token}/approve")
async def approve_escrow(
    token: str,
    approver_did: str = Query(...),
    signature: str = Query(...),
) -> JSONResponse:
    success, message = ESCROW_STORE.approve(token, approver_did)
    if not success:
        raise HTTPException(400, message)
    return JSONResponse({"status": "approved", "message": message})


# ---------------------------------------------------------------------------
# Endpoint: GET /v1/proxy/escrow/{token}/release
# ---------------------------------------------------------------------------

@app.get("/v1/proxy/escrow/{token}/release")
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

@app.get("/v1/proxy/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        model_version_hash=MODEL_VERSION_HASH,
        schema_version="0.2.0-draft",
        public_key_b64=PROXY_KEYPAIR.public_key_b64,  # fix C: clients verify receipts against this
    )


# NOTE: The keypair is ephemeral (regenerated on restart). Production deployments
# must load from a persistent, hardware-backed key store (HSM, cloud KMS, or
# encrypted key file) so that receipt signatures remain verifiable across restarts.


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run() -> None:
    uvicorn.run("five_h_proxy.proxy:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    run()
