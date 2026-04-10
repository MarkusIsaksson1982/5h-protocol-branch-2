"""
five_h_proxy/consent.py

ConsentReceipt chain management.

Fixes applied (Gemini review 2026-04-12):
  B. Merkle second-preimage: domain separation bytes added
       0x00 prefix on leaf nodes, 0x01 prefix on internal nodes
  C. Synthetic signatures: now uses real Ed25519 via five_h_proxy.crypto
  D. Streaming redaction: file read in 64 KB chunks, not .read_text()
  + Async file I/O: ReceiptStore.append/load/delete are now async (aiofiles)

Authors: Claude (Anthropic)
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import aiofiles
import aiofiles.os

from .crypto import PROXY_KEYPAIR
from .models import ConsentReceipt, ReceiptMode


_CHUNK_SIZE = 65_536  # 64 KB


# ---------------------------------------------------------------------------
# Merkle root with domain separation (fix B)
# ---------------------------------------------------------------------------

def _sha256_leaf(data: str) -> str:
    """Hash a leaf node with 0x00 domain prefix."""
    return hashlib.sha256(b"\x00" + data.encode()).hexdigest()


def _sha256_internal(left: str, right: str) -> str:
    """Hash an internal node with 0x01 domain prefix."""
    return hashlib.sha256(b"\x01" + (left + right).encode()).hexdigest()


def compute_merkle_root(receipts: list[ConsentReceipt]) -> str:
    """
    Compute a binary Merkle root over receipt action_hashes.

    Domain separation prevents second-preimage attacks:
      - Leaf nodes:     sha256(0x00 || action_hash)
      - Internal nodes: sha256(0x01 || left || right)

    Empty list -> sha256(0x00 || "") (deterministic).
    """
    if not receipts:
        return _sha256_leaf("")

    current = [_sha256_leaf(r.action_hash) for r in receipts]

    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else left
            next_level.append(_sha256_internal(left, right))
        current = next_level

    return current[0]


# ---------------------------------------------------------------------------
# Receipt factory
# ---------------------------------------------------------------------------

def build_action_hash(
    request_id: str,
    hop_number: int,
    decision: str,
    timestamp: datetime,
) -> str:
    canonical = json.dumps(
        {
            "request_id": request_id,
            "hop_number": hop_number,
            "decision": decision,
            "timestamp": timestamp.isoformat(),
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def make_receipt(
    request_id: uuid.UUID,
    hop_number: int,
    proxy_did: str,
    decision: str,
    prior_receipts: list[ConsentReceipt],
    receipt_mode: ReceiptMode,
    model_version_hash: str | None,
) -> ConsentReceipt:
    """
    Produce a ConsentReceipt for the current hop.

    Signature is a real Ed25519 signature (fix C) over:
      action_hash || chain_root_hash || receipt_mode
    using PROXY_KEYPAIR. Verifiable against the public key at /v1/proxy/health.
    """
    now = datetime.now(tz=timezone.utc)
    action_hash = build_action_hash(str(request_id), hop_number, decision, now)

    # Build placeholder to include this receipt in chain root computation
    placeholder = ConsentReceipt(
        receipt_id=uuid.uuid4(),
        hop_number=hop_number,
        proxy_did=proxy_did,
        timestamp=now,
        action_hash=action_hash,
        receipt_mode=receipt_mode,
        model_version_hash=model_version_hash,
        signature="PLACEHOLDER",
    )
    chain_root = compute_merkle_root(prior_receipts + [placeholder])

    # Real Ed25519 signature (fix C)
    sig_input = f"{action_hash}:{chain_root}:{receipt_mode.value}"
    signature = PROXY_KEYPAIR.sign(sig_input)

    return ConsentReceipt(
        receipt_id=uuid.uuid4(),
        hop_number=hop_number,
        proxy_did=proxy_did,
        timestamp=now,
        action_hash=action_hash,
        chain_root_hash=chain_root if receipt_mode != ReceiptMode.FULL_CHAIN else None,
        receipt_mode=receipt_mode,
        model_version_hash=model_version_hash,
        signature=signature,
    )


# ---------------------------------------------------------------------------
# Append-only async JSONL store
# ---------------------------------------------------------------------------

class ReceiptStore:
    """
    Append-only file-based store for ConsentReceipts.
    One JSONL file per request_id. All I/O is async (fix: Gemini rec).

    In production: replace with an immutable log (append-only Postgres,
    LMDB, or a dedicated audit log service).
    """

    def __init__(self, store_dir: Path) -> None:
        self.store_dir = store_dir
        store_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, request_id: str) -> Path:
        return self.store_dir / f"{request_id}.jsonl"

    async def append(self, request_id: str, receipt: ConsentReceipt) -> None:
        line = receipt.model_dump_json() + "\n"
        async with aiofiles.open(self._path(request_id), "a") as fh:
            await fh.write(line)

    async def load_chain(self, request_id: str) -> list[ConsentReceipt]:
        path = self._path(request_id)
        if not path.exists():
            return []
        receipts = []
        async with aiofiles.open(path) as fh:
            async for line in fh:
                if line.strip():
                    receipts.append(ConsentReceipt.model_validate_json(line))
        return receipts

    async def merkle_root(self, request_id: str) -> str:
        return compute_merkle_root(await self.load_chain(request_id))

    async def delete(self, request_id: str) -> str:
        """
        Redaction: stream file in chunks to compute hash, then delete.
        Returns tombstone hash.

        Fix D: streams in 64 KB chunks rather than loading entire file into
        memory. A maliciously inflated receipt chain cannot cause OOM here.
        """
        path = self._path(request_id)
        if not path.exists():
            return hashlib.sha256(b"EMPTY").hexdigest()

        h = hashlib.sha256()
        async with aiofiles.open(path, "rb") as fh:
            while chunk := await fh.read(_CHUNK_SIZE):
                h.update(chunk)
        content_hash = h.hexdigest()

        await aiofiles.os.remove(path)

        tombstone_input = f"DELETED:{request_id}:{content_hash}".encode()
        return hashlib.sha256(tombstone_input).hexdigest()
