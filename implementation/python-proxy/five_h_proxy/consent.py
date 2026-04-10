"""
five_h_proxy/consent.py

ConsentReceipt chain management.

Each hop appends a signed receipt to an append-only JSONL file.
When the chain closes, computes a Merkle root over all receipt hashes.

receipt_mode semantics (from spec/schemas/ai-proxy.json):
  "full_chain"  – all receipts returned; intermediary DIDs visible to target
  "merkle_root" – only root hash returned; full chain held locally for audit
  "blind"       – stub: blind-signature scheme (planned, not yet implemented)

Authors: Claude, Anthropic
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .models import ConsentReceipt, ReceiptMode


# ---------------------------------------------------------------------------
# Merkle root computation
# ---------------------------------------------------------------------------

def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def compute_merkle_root(receipts: list[ConsentReceipt]) -> str:
    """
    Compute a simple binary Merkle root over receipt action_hashes.
    Empty list → hash of empty string (deterministic).
    """
    leaves = [r.action_hash for r in receipts]
    if not leaves:
        return _sha256("")

    current = leaves[:]
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else left  # duplicate last if odd
            next_level.append(_sha256(left + right))
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
            "request_id": str(request_id),
            "hop_number": hop_number,
            "decision": decision,
            "timestamp": timestamp.isoformat(),
        },
        sort_keys=True,
    )
    return _sha256(canonical)


def make_receipt(
    request_id: uuid.UUID,
    hop_number: int,
    proxy_did: str,
    decision: str,
    prior_receipts: list[ConsentReceipt],
    receipt_mode: ReceiptMode,
    model_version_hash: str | None,
    proxy_signing_key: str = "SYNTHETIC_SIGNATURE",
) -> ConsentReceipt:
    """
    Produce a ConsentReceipt for the current hop.

    In production, proxy_signing_key would be the proxy's Ed25519 private key
    and we would produce a real signature. For now, the signature is a
    deterministic synthetic placeholder for test-vector compatibility.
    """
    now = datetime.now(tz=timezone.utc)
    action_hash = build_action_hash(str(request_id), hop_number, decision, now)

    all_receipts_so_far = prior_receipts + [
        # temporary placeholder to include this receipt in root
        ConsentReceipt(
            receipt_id=uuid.uuid4(),
            hop_number=hop_number,
            proxy_did=proxy_did,
            timestamp=now,
            action_hash=action_hash,
            receipt_mode=receipt_mode,
            model_version_hash=model_version_hash,
            signature="PLACEHOLDER",
        )
    ]
    chain_root = compute_merkle_root(all_receipts_so_far)

    # Signature: in production sign over (action_hash || chain_root || receipt_mode)
    signature_input = f"{action_hash}:{chain_root}:{receipt_mode.value}"
    signature = _sha256(signature_input + proxy_signing_key)  # synthetic

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
# Append-only JSONL store
# ---------------------------------------------------------------------------

class ReceiptStore:
    """
    Append-only file-based store for ConsentReceipts.
    One JSONL file per request_id.
    In production, replace with an immutable log (e.g., LMDB, append-only Postgres table).
    """

    def __init__(self, store_dir: Path) -> None:
        self.store_dir = store_dir
        store_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, request_id: str) -> Path:
        return self.store_dir / f"{request_id}.jsonl"

    def append(self, request_id: str, receipt: ConsentReceipt) -> None:
        line = receipt.model_dump_json() + "\n"
        with self._path(request_id).open("a") as fh:
            fh.write(line)

    def load_chain(self, request_id: str) -> list[ConsentReceipt]:
        path = self._path(request_id)
        if not path.exists():
            return []
        receipts = []
        for line in path.read_text().splitlines():
            if line.strip():
                receipts.append(ConsentReceipt.model_validate_json(line))
        return receipts

    def merkle_root(self, request_id: str) -> str:
        return compute_merkle_root(self.load_chain(request_id))

    def delete(self, request_id: str) -> str:
        """
        Redaction: delete the JSONL file and return a tombstone hash.
        The tombstone proves deletion without reproducing deleted content.
        """
        path = self._path(request_id)
        content_hash = "EMPTY"
        if path.exists():
            content_hash = _sha256(path.read_text())
            path.unlink()

        tombstone_input = f"DELETED:{request_id}:{content_hash}"
        return _sha256(tombstone_input)
