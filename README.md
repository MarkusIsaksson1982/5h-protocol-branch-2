# 5H Protocol – Branch 2: Claude-led Implementation Track

**Status:** Active implementation branch  
**Forked from:** `MarkusIsaksson1982/5h-protocol` main repo (2026-04-10 consolidation)  
**Leadership:** Claude (Anthropic) – primary technical direction  
**Primary collaborator:** ChatGPT / Codex (OpenAI) – code generation and execution semantics  
**Polling branch:** Gemini (Google) – privacy primitives and bridge contracts  
**Sibling branch:** `MarkusIsaksson1982/5h-protocol-branch-1` (Grok + Muse Spark – Rust core engine)

---

## What this branch owns

Branch-1 (Grok-led) is building the **Rust core graph engine** bottom-up. This branch builds the **Python AI proxy reference server** top-down from the JSON Schema contracts, the **OpenAPI specification**, the **formal test suite**, and the **trust/alignment middleware layer** derived from ChatGPT's H-T (Trust Layer) concept.

The two branches are intentionally non-overlapping at the code level. When both are stable, the Rust engine and the Python proxy connect via HTTP — the Rust core handles graph traversal and path-finding; the Python server handles AI model interaction, consent receipts, escrow, and redaction.

| Layer | Branch 1 (Grok + Muse Spark) | Branch 2 (Claude + Codex) |
|---|---|---|
| Graph engine | Rust (`petgraph`-based) | ← consumed as dependency |
| Path-finding | Rust (BFS + Laplace DP) | ← API client |
| AI proxy server | Planned (Python, later) | **Python (FastAPI) – this branch** |
| Trust middleware | — | **H-T layer (this branch)** |
| OpenAPI spec | — | **This branch** |
| Formal test suite | Rust unit tests | **pytest + integration (this branch)** |
| TypeScript client | Planned (branch-1 backlog) | Deferred until proxy API is stable |

---

## Repository layout

```
/
├── README.md                        ← this file
├── PROTOCOL.md                      ← frozen v0.2 spec (identical to branch-1)
├── spec/                            ← normative schemas and test vectors
│   ├── schemas/
│   │   ├── graph-model.json         ← copy from main repo (Claude-authored)
│   │   └── ai-proxy.json            ← copy from main repo (Claude-authored)
│   ├── test-vectors/
│   │   └── 15-node-graph.json       ← copy from main repo (Claude-authored)
│   ├── threat-model.md              ← copy from main repo (Claude-authored)
│   └── openapi/
│       └── proxy-api.yaml           ← this branch (derived from ai-proxy.json)
├── implementation/
│   └── python-proxy/                ← this branch's primary deliverable
│       ├── pyproject.toml
│       ├── five_h_proxy/
│       │   ├── __init__.py
│       │   ├── models.py            ← Pydantic v2 models from JSON Schema
│       │   ├── proxy.py             ← FastAPI server (all four endpoints)
│       │   ├── trust_layer.py       ← H-T middleware (intent scoring, adversarial detection)
│       │   ├── consent.py           ← ConsentReceipt chain management
│       │   ├── escrow.py            ← Escrow store and release logic
│       │   └── rate_limit.py        ← Per-tier rate limiting
│       └── tests/
│           ├── test_models.py       ← Schema conformance tests
│           ├── test_proxy.py        ← Endpoint integration tests
│           └── test_15_node.py      ← Full test vector assertions
└── commentary/
    └── models/
        ├── claude-anthropic/        ← Claude's decision log for this branch
        └── chatgpt-openai/          ← Codex/ChatGPT contributions
```

---

## Quick start

```bash
git clone https://github.com/MarkusIsaksson1982/5h-protocol-branch-2.git
cd 5h-protocol-branch-2/implementation/python-proxy
pip install -e ".[test]"
uvicorn five_h_proxy.proxy:app --reload       # start server on :8000
pytest tests/                                  # run test suite
```

The test suite loads `spec/test-vectors/15-node-graph.json` and asserts all 10 expected behaviors from the test vector `_expected_behaviors.implementation_checklist`.

---

## Branch governance

- All new design decisions are proposed as artifacts in `commentary/models/claude-anthropic/` before code is written.
- ChatGPT/Codex reviews every pull request against the execution semantics defined in `spec/execution/` (carried forward from the main repo).
- Gemini is polled for bridge and privacy-primitive review before any bridge-related code is merged.
- Branch-1 is polled at intervals for Rust API surface changes that affect the HTTP contract between the two components.
- No code is merged without passing `pytest tests/test_15_node.py` in full.

---

**Signed:** Claude, Anthropic (branch lead)  
**Co-signed:** ChatGPT / Codex, OpenAI (primary collaborator)
