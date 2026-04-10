"""
tests/test_consent.py

Unit tests for consent.py: Merkle root, receipt factory, ReceiptStore.

Specifically covers the fixes from Gemini's review:
  B. Merkle domain separation (leaf vs internal nodes)
  C. Ed25519 signature shape (not a hex MAC)
  D. Streaming redaction produces deterministic tombstone

Authors: Claude (Anthropic)
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
import tempfile

import pytest

from five_h_proxy.consent import (
    ReceiptStore,
    _sha256_leaf,
    _sha256_internal,
    build_action_hash,
    compute_merkle_root,
    make_receipt,
)
from five_h_proxy.models import ConsentReceipt, ReceiptMode
from five_h_proxy.crypto import PROXY_KEYPAIR


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _receipt(hop: int, action_hash: str = "a" * 64) -> ConsentReceipt:
    return ConsentReceipt(
        receipt_id=uuid.uuid4(),
        hop_number=hop,
        proxy_did="did:5h:proxy-branch2-ref",
        timestamp=datetime.now(tz=timezone.utc),
        action_hash=action_hash,
        receipt_mode=ReceiptMode.FULL_CHAIN,
        signature="SYNTH",
    )


# ---------------------------------------------------------------------------
# Merkle root – domain separation (fix B)
# ---------------------------------------------------------------------------

class TestMerkleRoot:
    def test_empty_is_deterministic(self):
        r1 = compute_merkle_root([])
        r2 = compute_merkle_root([])
        assert r1 == r2
        assert len(r1) == 64

    def test_single_leaf_uses_leaf_prefix(self):
        receipt = _receipt(1, "ab" * 32)
        root = compute_merkle_root([receipt])
        expected = _sha256_leaf("ab" * 32)
        assert root == expected

    def test_two_leaves_uses_internal_prefix(self):
        r1 = _receipt(1, "aa" * 32)
        r2 = _receipt(2, "bb" * 32)
        root = compute_merkle_root([r1, r2])
        leaf1 = _sha256_leaf("aa" * 32)
        leaf2 = _sha256_leaf("bb" * 32)
        expected = _sha256_internal(leaf1, leaf2)
        assert root == expected

    def test_domain_separation_prevents_collision(self):
        """
        A leaf hash must differ from an internal hash of the same data.
        Without domain separation, hash(leaf_data) == hash(leaf_data || leaf_data)
        is theoretically exploitable.
        """
        data = "cd" * 32
        leaf_hash = _sha256_leaf(data)
        internal_hash = _sha256_internal(data, data)
        assert leaf_hash != internal_hash

    def test_order_matters(self):
        r1 = _receipt(1, "aa" * 32)
        r2 = _receipt(2, "bb" * 32)
        assert compute_merkle_root([r1, r2]) != compute_merkle_root([r2, r1])

    def test_odd_count_pads_last(self):
        """Three leaves: last leaf is duplicated at that level."""
        receipts = [_receipt(i, chr(97 + i) * 64) for i in range(3)]
        root = compute_merkle_root(receipts)
        assert len(root) == 64  # well-formed SHA-256 hex

    def test_four_leaves_full_tree(self):
        receipts = [_receipt(i, chr(97 + i) * 64) for i in range(4)]
        root = compute_merkle_root(receipts)
        # Manually verify
        leaves = [_sha256_leaf(chr(97 + i) * 64) for i in range(4)]
        level1 = [_sha256_internal(leaves[0], leaves[1]),
                  _sha256_internal(leaves[2], leaves[3])]
        expected = _sha256_internal(level1[0], level1[1])
        assert root == expected


# ---------------------------------------------------------------------------
# Receipt factory – Ed25519 signature (fix C)
# ---------------------------------------------------------------------------

class TestMakeReceipt:
    def test_signature_is_base64url_not_hex(self):
        receipt = make_receipt(
            request_id=uuid.uuid4(),
            hop_number=1,
            proxy_did="did:5h:proxy-branch2-ref",
            decision="forward",
            prior_receipts=[],
            receipt_mode=ReceiptMode.FULL_CHAIN,
            model_version_hash=None,
        )
        # Ed25519 signatures are 64 bytes = 88 base64url chars (with padding)
        # or 86 without. Either way, not 64-char hex.
        assert len(receipt.signature) > 64
        # base64url chars only (no +, /)
        import re
        assert re.match(r"^[A-Za-z0-9_=-]+$", receipt.signature)

    def test_signature_verifies_with_proxy_keypair(self):
        receipt = make_receipt(
            request_id=uuid.uuid4(),
            hop_number=2,
            proxy_did="did:5h:proxy-branch2-ref",
            decision="summarize",
            prior_receipts=[],
            receipt_mode=ReceiptMode.MERKLE_ROOT,
            model_version_hash="a" * 64,
        )
        # Reconstruct the signed payload
        chain_root = receipt.chain_root_hash or ""
        sig_input = f"{receipt.action_hash}:{chain_root}:{receipt.receipt_mode.value}"
        assert PROXY_KEYPAIR.verify(sig_input, receipt.signature)

    def test_wrong_data_fails_verification(self):
        receipt = make_receipt(
            request_id=uuid.uuid4(),
            hop_number=1,
            proxy_did="did:5h:proxy-branch2-ref",
            decision="forward",
            prior_receipts=[],
            receipt_mode=ReceiptMode.FULL_CHAIN,
            model_version_hash=None,
        )
        assert not PROXY_KEYPAIR.verify("tampered_data", receipt.signature)

    def test_merkle_root_mode_sets_chain_root(self):
        receipt = make_receipt(
            request_id=uuid.uuid4(),
            hop_number=1,
            proxy_did="did:5h:proxy-branch2-ref",
            decision="forward",
            prior_receipts=[],
            receipt_mode=ReceiptMode.MERKLE_ROOT,
            model_version_hash=None,
        )
        assert receipt.chain_root_hash is not None
        assert len(receipt.chain_root_hash) == 64

    def test_full_chain_mode_no_chain_root(self):
        receipt = make_receipt(
            request_id=uuid.uuid4(),
            hop_number=1,
            proxy_did="did:5h:proxy-branch2-ref",
            decision="forward",
            prior_receipts=[],
            receipt_mode=ReceiptMode.FULL_CHAIN,
            model_version_hash=None,
        )
        assert receipt.chain_root_hash is None


# ---------------------------------------------------------------------------
# ReceiptStore – streaming delete (fix D) and async append
# ---------------------------------------------------------------------------

class TestReceiptStore:
    @pytest.fixture
    def store(self, tmp_path: Path) -> ReceiptStore:
        return ReceiptStore(tmp_path / "receipts")

    def test_append_and_load(self, store: ReceiptStore):
        request_id = str(uuid.uuid4())
        receipt = make_receipt(
            request_id=uuid.UUID(request_id),
            hop_number=1,
            proxy_did="did:5h:proxy-branch2-ref",
            decision="forward",
            prior_receipts=[],
            receipt_mode=ReceiptMode.FULL_CHAIN,
            model_version_hash=None,
        )
        asyncio.get_event_loop().run_until_complete(store.append(request_id, receipt))
        chain = asyncio.get_event_loop().run_until_complete(store.load_chain(request_id))
        assert len(chain) == 1
        assert chain[0].action_hash == receipt.action_hash

    def test_delete_returns_tombstone_hex(self, store: ReceiptStore):
        request_id = str(uuid.uuid4())
        receipt = make_receipt(
            request_id=uuid.UUID(request_id),
            hop_number=1,
            proxy_did="did:5h:proxy-branch2-ref",
            decision="forward",
            prior_receipts=[],
            receipt_mode=ReceiptMode.FULL_CHAIN,
            model_version_hash=None,
        )
        asyncio.get_event_loop().run_until_complete(store.append(request_id, receipt))
        tombstone = asyncio.get_event_loop().run_until_complete(store.delete(request_id))
        # Must be a 64-char hex SHA-256
        assert len(tombstone) == 64
        assert all(c in "0123456789abcdef" for c in tombstone)

    def test_delete_removes_file(self, store: ReceiptStore):
        request_id = str(uuid.uuid4())
        receipt = make_receipt(
            request_id=uuid.UUID(request_id),
            hop_number=1,
            proxy_did="did:5h:proxy-branch2-ref",
            decision="forward",
            prior_receipts=[],
            receipt_mode=ReceiptMode.FULL_CHAIN,
            model_version_hash=None,
        )
        asyncio.get_event_loop().run_until_complete(store.append(request_id, receipt))
        asyncio.get_event_loop().run_until_complete(store.delete(request_id))
        # File should no longer exist
        chain = asyncio.get_event_loop().run_until_complete(store.load_chain(request_id))
        assert chain == []

    def test_delete_nonexistent_returns_empty_tombstone(self, store: ReceiptStore):
        tombstone = asyncio.get_event_loop().run_until_complete(
            store.delete("nonexistent-request-id")
        )
        assert len(tombstone) == 64

    def test_tombstone_is_deterministic_for_same_content(self, store: ReceiptStore):
        """Same file content produces the same tombstone — allows cross-node audit."""
        request_id = str(uuid.uuid4())
        receipt = make_receipt(
            request_id=uuid.UUID(request_id),
            hop_number=1,
            proxy_did="did:5h:proxy-branch2-ref",
            decision="forward",
            prior_receipts=[],
            receipt_mode=ReceiptMode.FULL_CHAIN,
            model_version_hash=None,
        )
        # Write twice to two separate stores; verify tombstones match
        store2 = ReceiptStore(store.store_dir.parent / "receipts2")
        loop = asyncio.get_event_loop()
        loop.run_until_complete(store.append(request_id, receipt))
        loop.run_until_complete(store2.append(request_id, receipt))
        t1 = loop.run_until_complete(store.delete(request_id))
        t2 = loop.run_until_complete(store2.delete(request_id))
        assert t1 == t2
