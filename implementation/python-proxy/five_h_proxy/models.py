"""
five_h_proxy/models.py

Pydantic v2 models derived directly from:
  spec/schemas/graph-model.json
  spec/schemas/ai-proxy.json

These are the canonical Python representations of the 5H Protocol data
structures. Any change to the JSON Schemas must be reflected here.

Authors: Claude (Anthropic) – initial definition
         ChatGPT/Codex (OpenAI) – review and iteration
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from enum import Enum
from typing import Annotated, Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Shared primitives
# ---------------------------------------------------------------------------

DID = Annotated[str, Field(pattern=r"^did:[a-z0-9]+:.+$")]
UUIDv7 = UUID  # runtime: any UUID accepted; generation should use uuid7


class KeyAlg(str, Enum):
    ED25519 = "ed25519"
    ML_DSA_87 = "ml-dsa-87"
    ECDSA_P256 = "ecdsa-p256"


class VerificationLevel(int, Enum):
    UNVERIFIED = 0
    SOCIAL = 1
    GOVERNMENT = 2


class Visibility(str, Enum):
    PUBLIC = "public"
    FOF = "fof"
    VERIFIED = "verified"
    CUSTOM = "custom"


class NodeType(str, Enum):
    INDIVIDUAL = "individual"
    ORGANIZATION = "organization"
    ARTIFICIAL_INTERIM = "artificial_interim"
    BRIDGE = "bridge"


class EdgeType(str, Enum):
    HANDSHAKE = "handshake"
    ORG_INTERNAL = "org_internal"
    VERIFIED_LINK = "verified_link"
    BRIDGE_RELAY = "bridge_relay"


class EdgeStrength(str, Enum):
    STRONG = "strong"
    WEAK = "weak"
    FOF = "fof"


class GatewayConsent(str, Enum):
    VOLUNTARY = "voluntary"
    ROLE_REQUIRED = "role_required"


class AcceptPolicy(str, Enum):
    ACCEPT_ANY = "accept-any"
    VERIFIED_ONLY = "verified-only"
    REQUIRES_INTENT = "requires-intent-description"
    CUSTOM = "custom"


class ProxyCapability(str, Enum):
    SUMMARIZATION = "summarization"
    TRANSLATION = "translation"
    TONE_MATCHING = "tone-matching"
    NEUTRALITY = "neutrality-enforcement"
    ESCROW = "escrow"


# ---------------------------------------------------------------------------
# Graph model (from spec/schemas/graph-model.json)
# ---------------------------------------------------------------------------

class PublicKey(BaseModel):
    key_alg: KeyAlg
    key_value: str  # base64url-encoded


class AiProxyConfig(BaseModel):
    model: str
    model_version_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    instructions: str
    capabilities: list[ProxyCapability] = Field(default_factory=list)
    consent_expiry: datetime | None = None


class OrgPolicy(BaseModel):
    accept_policy: AcceptPolicy = AcceptPolicy.VERIFIED_ONLY
    interim_node_count_min: int = Field(default=1, ge=0)
    interim_node_count_max: int = Field(default=3, ge=0)


class MetadataStripPolicy(BaseModel):
    strips_requester_did: bool = False
    strips_consent_receipts: bool = False
    strips_verification_level: bool = False
    strips_intent_structured: bool = False


class BridgeConfig(BaseModel):
    external_network: str
    metadata_strip_policy: MetadataStripPolicy
    attestation_signature: str  # synthetic placeholder in tests


class VouchBudget(BaseModel):
    credits_remaining: int = Field(ge=0)
    credits_max: int = Field(ge=0)
    last_restore_timestamp: datetime


class Node(BaseModel):
    id: DID
    type: NodeType
    verification_level: VerificationLevel
    public_key: PublicKey
    visibility: Visibility
    acl_list: list[DID] = Field(default_factory=list)
    blocklist: list[DID] = Field(default_factory=list)
    ai_proxy_allowed: bool = False
    ai_proxy_config: AiProxyConfig | None = None
    gateway_consent: GatewayConsent | None = None
    org_policy: OrgPolicy | None = None
    bridge_config: BridgeConfig | None = None
    vouch_budget: VouchBudget | None = None
    # test-vector annotation field; ignored in production
    label: str | None = None

    @model_validator(mode="after")
    def check_ai_proxy_config_present_if_allowed(self) -> Node:
        if self.ai_proxy_allowed and self.ai_proxy_config is None:
            raise ValueError("ai_proxy_config is required when ai_proxy_allowed=True")
        return self

    def blocks(self, did: str) -> bool:
        return did in self.blocklist

    def is_expired_proxy(self) -> bool:
        if self.ai_proxy_config and self.ai_proxy_config.consent_expiry:
            from datetime import timezone
            return datetime.now(tz=timezone.utc) > self.ai_proxy_config.consent_expiry
        return False


class Edge(BaseModel):
    from_did: str = Field(alias="from")
    to_did: str = Field(alias="to")
    type: EdgeType
    strength: EdgeStrength | None = None
    mutual_consent: bool
    timestamp: datetime
    vouched_by: DID | None = None
    crdt_vector_clock: dict[str, int] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}

    @field_validator("mutual_consent")
    @classmethod
    def must_be_mutual(cls, v: bool) -> bool:
        if not v:
            raise ValueError("mutual_consent MUST be True; edges without mutual consent are invalid")
        return v


class EdgeRevocation(BaseModel):
    revoked_edge_from: DID
    revoked_edge_to: DID
    revocation_timestamp: datetime
    deletion_proof: str
    broadcast_signature: str


class FiveHGraph(BaseModel):
    """
    In-memory representation of the full 5H graph.
    Loaded from spec/test-vectors/15-node-graph.json or a live store.
    """
    schema_version: str = "0.2.0-draft"
    nodes: list[Node]
    edges: list[Edge]
    revocation_log: list[EdgeRevocation] = Field(default_factory=list)

    def node_by_did(self, did: str) -> Node | None:
        for n in self.nodes:
            if n.id == did:
                return n
        return None

    def revoked_pairs(self) -> set[tuple[str, str]]:
        return {(r.revoked_edge_from, r.revoked_edge_to) for r in self.revocation_log}

    def active_edges(self) -> list[Edge]:
        revoked = self.revoked_pairs()
        return [
            e for e in self.edges
            if (e.from_did, e.to_did) not in revoked
        ]


# ---------------------------------------------------------------------------
# Wire protocol (from spec/schemas/ai-proxy.json)
# ---------------------------------------------------------------------------

class AnonymityLevel(str, Enum):
    FULL = "full"
    PSEUDONYM = "pseudonym"
    IDENTIFIED = "identified"


class PreferredOutcome(str, Enum):
    FORWARD = "forward"
    SUMMARIZE = "summarize"
    ESCROW = "escrow"
    CONNECT = "connect"


class ProxyDecision(str, Enum):
    FORWARD = "forward"
    REJECT = "reject"
    SUMMARIZE = "summarize"
    ESCROW = "escrow"
    ACCEPT_AND_CONNECT = "accept-and-connect"


class FailureClass(str, Enum):
    SOFT = "soft"   # retry with modifications
    HARD = "hard"   # requires rollback (blocklist hit)
    CRITICAL = "critical"  # abort + escalate (policy violation, prompt injection)


class ErrorCode(str, Enum):
    BLOCKLIST_HIT = "blocklist_hit"
    VERIFICATION_INSUFFICIENT = "verification_level_insufficient"
    RATE_LIMIT = "rate_limit_exceeded"
    TTL_EXPIRED = "ttl_expired"
    PROXY_CONFIG_MISMATCH = "proxy_config_mismatch"
    CONSENT_EXPIRED = "consent_expired"
    PROMPT_INJECTION = "prompt_injection_detected"
    POLICY_VIOLATION = "policy_violation"
    INTERNAL_ERROR = "internal_error"


class IntentType(str, Enum):
    PROFESSIONAL = "professional_inquiry"
    PERSONAL = "personal_connection"
    URGENT = "urgent_contact"
    COMMERCIAL = "commercial_proposal"
    RESEARCH = "research_collaboration"
    MEDIA = "media_request"
    OTHER = "other"


class ReceiptMode(str, Enum):
    FULL_CHAIN = "full_chain"
    MERKLE_ROOT = "merkle_root"
    BLIND = "blind"


class RequestIntent(BaseModel):
    intent_type: IntentType
    summary: str = Field(max_length=500)
    full_text: str | None = None  # encrypted at rest
    anonymity_level: AnonymityLevel


class ProxyAuthorization(BaseModel):
    proxy_did: DID
    model_version_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    consent_expiry: datetime | None = None
    requester_auth_signature: str
    target_auth_signature: str


class ConsentReceipt(BaseModel):
    receipt_id: UUIDv7
    hop_number: int = Field(ge=1)
    proxy_did: DID
    timestamp: datetime
    action_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    chain_root_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")] | None = None
    receipt_mode: ReceiptMode = ReceiptMode.FULL_CHAIN
    model_version_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")] | None = None
    signature: str


class ContactRequest(BaseModel):
    request_id: UUIDv7
    requester_did: DID
    target_did: DID
    hop_number: int = Field(ge=1, le=10)
    intent: RequestIntent
    preferred_outcome: PreferredOutcome
    consent_receipts: list[ConsentReceipt] = Field(default_factory=list)
    proxy_authorization: ProxyAuthorization | None = None
    rate_limit_token: str | None = None
    ttl_hops: int = Field(default=5, ge=1, le=9)
    signature: str
    encryption: str = "aes-256-gcm"


class ProxyError(BaseModel):
    code: ErrorCode
    message: str = Field(max_length=200)
    rate_limit_retry_after: datetime | None = None
    pow_challenge: str | None = None


class ProxyResponse(BaseModel):
    request_id: UUIDv7
    decision: ProxyDecision
    summary: str | None = Field(default=None, max_length=300)
    escrow_token: str | None = None
    next_hop_did: DID | None = None
    failure_class: FailureClass | None = None
    consent_receipt: ConsentReceipt
    error: ProxyError | None = None


class RedactionRequest(BaseModel):
    request_id: UUIDv7
    requester_did: DID
    signature: str


class RedactionProof(BaseModel):
    request_id: UUIDv7
    deletion_timestamp: datetime
    deletion_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    proxy_signature: str


class HealthResponse(BaseModel):
    status: str = "ok"
    model_version_hash: str
    schema_version: str = "0.2.0-draft"
    public_key_b64: str = ""  # Ed25519 public key; populated by proxy at startup (fix C)
