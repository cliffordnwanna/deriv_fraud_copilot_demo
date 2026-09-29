# Deriv Fraud Investigation Copilot

An AI-assisted fraud investigation system for financial operations teams.

The system combines deterministic fraud rules, statistical anomaly detection, policy-grounded LLM reasoning, and human-in-the-loop approval gates into a single investigation pipeline.

**AI investigates and recommends. Humans make consequential decisions.**

> This prototype uses synthetic investigation scenarios. It does not access Deriv production customer data.

---

## Architecture

```
Account Data
     │
     ▼
[Signal Agent]      — 9 deterministic fraud rules (Software 1.0)
     │
     ▼
[Pattern Agent]     — Statistical anomaly detection, Z-score (Software 2.0)
     │
     ▼
[Policy Agent]      — TF-IDF RAG over FATF / AML / Deriv T&C policies
     │
     ▼
[Reasoning Agent]   — Claude synthesises structured verdict (Software 3.0)
     │
     ▼
[Human Gate]        — Risk-tiered: CLEAR / REVIEW / ESCALATE / BLOCK
     │
     ▼
Audit Trail + Recommendation → Human Investigator Decision
```

Orchestrated via **LangGraph StateGraph** with conditional routing and error recovery.

---

## Investigation Scenarios

| ID | Type | Expected |
|---|---|---|
| CLEAN-001 | Normal trader | CLEAR |
| WASH-001 | Deposit → minimal trading → withdraw | ESCALATE/BLOCK |
| ATO-001 | Account takeover, Tor IP, geo shift | BLOCK |
| MULE-001 | 3 accounts sharing device/IP (fraud ring) | ESCALATE/BLOCK |
| VEL-001 | 500 trades/24h, 94% win rate | REVIEW/ESCALATE |

---

## Quickstart

```bash
# Install
python -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Run all scenarios (no API key needed)
python demo.py --scenario ALL

# Single scenario with full output
python demo.py --scenario MULE-001 --verbose

# With Claude reasoning (optional)
ANTHROPIC_API_KEY=sk-... python demo.py --scenario ALL

# REST API
python api.py
# → http://localhost:8000/docs
```

---

## Key Design Decisions

**Why three layers?** Each layer is auditable by a different audience: S1.0 for compliance officers, S2.0 for data scientists, S3.0 for investigators. Each is independently replaceable.

**Why LangGraph?** State machine with checkpointing and native human-in-the-loop interrupt support. The human gate is a first-class graph node, not bolted on.

**Why structured output with retry?** Same pattern as Deriv's Site Sense: enforce schema, validate before returning, retry with stricter prompt on parse failure.

**Why TF-IDF, not a vector DB?** Demo runs fully offline with no external model downloads. Production swap: Weaviate (Deriv's confirmed vector DB for Amy) — same interface, different client.

---

## Production Roadmap (90 days)

1. Connect to real Deriv WebSocket APIs (statement, account status)
2. Replace TF-IDF with Weaviate (same infra as Amy, different collection)
3. Replace Z-score with CoLES sequence embeddings (self-supervised, no labels)
4. Add GraphSAGE layer for network-level mule ring detection
5. Integrate human gate with Slack/email approval workflow
6. Connect audit trail to Datadog, build ThoughtSpot fraud KPI liveboard

---

## Safety

- No automated account restrictions without human approval
- Every investigation produces a full audit trail
- Policy citations are grounded in retrieved documents, not LLM memory
- Deterministic fallback if LLM is unavailable
- No customer data in this repository
