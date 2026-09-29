# Deriv Fraud Investigation Copilot

**Live demo:** https://2-29-54-185.sslip.io
**Repository:** https://github.com/cliffordnwanna/deriv_fraud_copilot_demo

An AI-assisted fraud investigation system for financial operations teams.

The system combines deterministic fraud rules, statistical anomaly detection, policy-grounded LLM reasoning, and human-in-the-loop approval gates into a single investigation pipeline.

**AI investigates and recommends. Humans make consequential decisions.**

> This prototype uses synthetic investigation scenarios. It does not access Deriv production customer data.

---

## Architecture

```
Account Data (synthetic scenario OR real SQLite account)
     │
     ▼
[Signal Agent]      — 9 deterministic fraud rules (Software 1.0)
     │
     ▼
[Pattern Agent]     — Statistical anomaly detection, Z-score (Software 2.0)
     │
     ▼
[Policy Agent]      — Embedding RAG over 30 real AML/CFT policies
     │                (FATF, FinCEN, FFIEC, OFAC, Wolfsberg, EU 5AMLD/MiFID II)
     ▼
[Reasoning Agent]   — OpenAI synthesises structured verdict (Software 3.0)
     │
     ▼
[Human Gate]        — Risk-tiered: CLEAR / REVIEW / ESCALATE / BLOCK
     │
     ▼
Audit Trail + Recommendation → Human Investigator Decision
```

Orchestrated via **LangGraph StateGraph** with conditional routing and error recovery (falls back to a sequential runner if LangGraph isn't installed).

---

## Data Sources

Two interchangeable inputs feed the same pipeline unmodified:

- **Synthetic scenarios** (`data/synthetic_scenarios.py`) — 5 hand-crafted cases matching Deriv's statement API response shape, useful for deterministic demos with no setup.
- **Real accounts** (`tools/data_connector.py` + `tools/data_normalizer.py`) — a 100-account SQLite dataset (`data/fraud_cases.db`, regenerated via `python data/generate_dataset.py`, seed 42) spanning 8 behavioural tables (accounts, transactions, trades, device fingerprints, complaints, login events, payment methods, linked accounts). The normalizer maps this into the same scenario shape the agents already consume, so no agent code branches on data source.

| ID | Type | Expected |
|---|---|---|
| CLEAN-001 | Normal trader | CLEAR |
| WASH-001 | Deposit → minimal trading → withdraw | ESCALATE/BLOCK |
| ATO-001 | Account takeover, Tor IP, geo shift | BLOCK |
| MULE-001 | 3 accounts sharing device/IP (fraud ring) | ESCALATE/BLOCK |
| VEL-001 | 500 trades/24h, 94% win rate | REVIEW/ESCALATE |

Ground-truth check across a stratified 24-account sample (`/investigate/{account_id}`): 4/4 CLEAN correctly CLEAR, 4/4 ATO correctly BLOCK, 4/4 MULE correctly BLOCK, 4/4 WASH and 4/4 VELOCITY correctly escalated.

---

## Quickstart

```bash
# Install
python -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Generate the real-account dataset (optional — synthetic scenarios work without it)
python data/generate_dataset.py

# Run all synthetic scenarios (no API key needed — deterministic fallback)
python demo.py --scenario ALL

# Single scenario with full output
python demo.py --scenario MULE-001 --verbose

# With OpenAI reasoning (optional)
OPENAI_API_KEY=sk-... python demo.py --scenario ALL

# REST API + browser UI
uvicorn api:app --port 8000
# → http://localhost:8000        (investigation UI)
# → http://localhost:8000/docs   (OpenAPI docs)
```

### Key endpoints

| Endpoint | Purpose |
|---|---|
| `GET /health` | Service status; reports which integrations are configured (never their values) |
| `GET /scenarios` | List synthetic scenario IDs |
| `GET /accounts` | List real accounts from the SQLite dataset, sorted by risk signal count |
| `POST /investigate/{id}` | Run the full pipeline — accepts a synthetic scenario ID or a real account ID |
| `GET /live/account` | Read-only balance/account check against your own authorised Deriv account via `DERIV_API_TOKEN` |
| `POST /slack/command`, `/slack/interactions` | Slack slash-command and button integration (demo-mode decisions only — no account actions) |

---

## Key Design Decisions

**Why three layers?** Each layer is auditable by a different audience: S1.0 for compliance officers, S2.0 for data scientists, S3.0 for investigators. Each is independently replaceable.

**Why LangGraph?** State machine with checkpointing and native human-in-the-loop interrupt support. The human gate is a first-class graph node, not bolted on.

**Why structured output with retry?** Enforce schema, validate before returning, retry with stricter prompt on parse failure.

**Why embeddings, not a second LLM call, for policy retrieval?** Which regulation applies needs to be grounded and auditable, not generated — an LLM asked to cite a policy ID can hallucinate a plausible but nonexistent one. Embedding similarity over a fixed, versioned policy corpus keeps citations real and keeps a second non-deterministic LLM hop out of a compliance-critical step. Falls back to deterministic keyword overlap if no API key is configured, so the agent never silently fails.

**Why is the AI never allowed to act directly?** The reasoning agent always produces a recommendation for human review — it never executes account restrictions, withdrawals, SAR filings, or trades. This applies uniformly across the API, the browser UI, and the Slack integration.

---

## Production Roadmap

1. Extend the real-account connector with device/IP/geolocation signals from an authorised internal source (the public Deriv API surface doesn't provide these — the connector says so explicitly rather than fabricating them)
2. Replace Z-score anomaly detection with CoLES sequence embeddings (self-supervised, no labels)
3. Add a GraphSAGE layer for network-level mule ring detection
4. Integrate the human gate with a case-management/approval workflow beyond Slack demo buttons
5. Connect the audit trail to a monitoring/observability stack

---

## Safety

- No automated account restrictions, withdrawals, SAR filings, or trades — every consequential action requires human approval
- Every investigation produces a full audit trail
- Policy citations are grounded in retrieved documents, not LLM memory
- Deterministic fallback if the LLM is unavailable
- Deriv API tokens are read-only account/balance checks, never exposed to the browser, and no trading/withdrawal operations are implemented
- No production customer data in this repository — `data/fraud_cases.db` is a deterministically generated synthetic dataset (seed 42), regenerated on deploy, not committed to git
