# Deriv Fraud Investigation Copilot
## Architecture & Interview Reference

---

## What It Is

A multi-agent fraud investigation prototype designed around a publicly visible fraud-investigation workflow. It is intended to assist investigators rather than autonomously make consequential account decisions.

**Problem it solves**: Deriv processes 168M+ monthly deals (~65/second). The prototype targets the investigator work of cross-referencing transaction history, geo/device signals, and AML policy. Deriv does not publicly disclose enough operational data for this prototype to claim a measured current manual workload. This system automates that investigation pipeline, produces a structured verdict in <1 second, and escalates to humans only when risk justifies it.

**Why now**: Deriv is actively hiring an Anti-Fraud Manager. Their careers material publicly references fraud signals including: "payment patterns, account behaviour, network overlaps."

> **Demo note**: Fraud cases in this demo use synthetic data generated to match Deriv's public WebSocket API shapes (api.deriv.com/api-explorer). The integration boundary is designed around real API patterns — one env var (`DERIV_API_TOKEN`) away from live data.

---

## Architecture (Three Software Layers — Prototype Framework)

```
INPUT (account ID + transaction data)
│
├─ SOFTWARE 1.0 ── Signal Agent (deterministic rules)
│   Rules: rapid withdrawal, wash pattern, new-account large TX,
│          geo/device mismatch, device overlap, high win rate,
│          velocity spike, crypto withdrawal, round-amount structuring
│   Output: triggered rules + composite risk score + risk tier
│
├─ SOFTWARE 2.0 ── Pattern Agent (statistical anomaly detection)
│   Features: wash ratio, velocity, inter-arrival times, amount distribution
│   Detectors: Z-score amount anomaly, velocity spike, wash ratio, concentration
│   Output: anomaly score 0.0–1.0 + detected patterns
│   [Production: swap for CoLES sequence embeddings → GraphSAGE network scoring]
│
├─ SOFTWARE 2.5 ── Policy Agent (RAG over AML/fraud policies)
│   Corpus: FATF Rec 10/20, EU 6AMLD, Deriv T&Cs, typology reports
│   Vector store: TF-IDF (demo) / Weaviate (production, matches Deriv's stack)
│   Output: policy context + applicable regulations + escalation action
│
└─ SOFTWARE 3.0 ── Reasoning Agent (Claude API)
    Input: all three agent outputs combined
    Output: structured JSON verdict (schema-enforced, retry on parse failure)
    Fields: verdict, confidence, primary_concern, reasoning,
            recommended_action, policy_citations, evidence_summary,
            human_review_required, sar_required
    Fallback: deterministic verdict from signal+pattern data if API unavailable

ORCHESTRATION: LangGraph StateGraph
    - Conditional routing (error → error_handler, not crash)
    - Each node is independently observable
    - Human-gate state is explicit; production approval persistence is a next step

HUMAN GATE (risk-tiered):
    CLEAR    → No consequential action; continue monitoring
    REVIEW   → Compliance queue, 48h SLA
    ESCALATE → Withdrawal hold, senior officer 24h, source-of-funds request
    BLOCK    → Immediate restriction, SAR filed, evidence preserved

AUDIT TRAIL: Every step logged with agent output, timestamp, model used
API: FastAPI REST endpoints → integrate with Deriv's existing tooling
```

---

## Key Design Decisions

### Why LangGraph for orchestration?
- Explicit state-machine workflow with conditional routing
- Supports checkpointing and human-in-the-loop interrupts when deployed with the appropriate persistence/checkpointer
- The human gate is represented as a first-class workflow stage
- Same pattern Deriv uses in their QA Loop (Discovery + Verifier agents) and SDLC pipeline (Planner + Builder + Verifier)

### Why separate the three software layers?
- Each layer explains a different thing to a different audience
  - S1.0 = compliance officer ("which rule did it break?")
  - S2.0 = data scientist ("how anomalous is this statistically?")
  - S3.0 = investigator ("what does this mean and what do I do?")
- Each layer is independently auditable and independently replaceable
- Matches Deriv's own public framing of their AI strategy

### Why structured output with retry?
- Same pattern from Deriv's Site Sense article: "AI responses were unpredictable — we enforced structured prompts with explicit format requirements and added a response parser that validates before returning. If parsing fails, retry with a stricter prompt."
- System never returns unstructured text to downstream consumers

### Why TF-IDF for the demo, Weaviate for production?
- The demo uses a self-contained TF-IDF retriever so it has no external vector-store dependency
- A production implementation could use a vector database such as Weaviate if that matches the target environment; the retrieval contract remains the important boundary
- Demo runs entirely offline with no external model downloads

### Why synthetic data that matches Deriv's API shapes?
- Deriv's WebSocket API shapes are public (api.deriv.com/api-explorer)
- Every field in the synthetic data matches the real `statement` response schema
- When Deriv gives us API access, swap `get_scenario()` for `fetch_statement(api_token)`
- Production would require an authenticated adapter, schema validation, access controls, and a proper data-ingestion path

---

## What This Addresses That Amy Doesn't

Amy is a customer-facing assistant. Based on Deriv's public documentation and engineering blog, there is no publicly documented investigator-facing fraud investigation copilot in Deriv's current tooling. This system is a compliance-internal tool, not a customer-facing product. It serves the anti-fraud investigator, not the end user.

Specifically, this system handles:
- Cross-account pattern detection (shared device/IP across mule rings)
- Structured AML policy retrieval with regulatory citation
- Risk-tiered escalation workflow with human approval gate
- Audit trail for SAR evidence preservation

---

## Production Path (What I'd Build in 90 Days at Deriv)

**Week 1–2**: Connect to real Deriv APIs (statement, account status, portfolio) using their WebSocket auth
**Week 3–4**: Replace TF-IDF with Weaviate (already running for Amy — same infra, different collection)
**Week 5–6**: Replace Pattern Agent's Z-score with FRL-System CoLES embeddings (sequence model trained on Deriv's own transaction history → no labels needed, self-supervised)
**Week 7–8**: Add GraphSAGE layer for network-level detection (shared devices/IPs across account graph)
**Week 9–10**: Integrate Human Gate with Slack/email approval workflow
**Week 11–12**: Connect audit trail to Datadog (already in Deriv's stack), build ThoughtSpot Liveboard for fraud KPIs

**Illustrative business case**: Before production, measure investigation volume, median handling time, false-positive rate, and analyst acceptance. For example only, if a pilot reduced 10 two-hour cases/week by 60%, that would represent roughly 12 analyst-hours/week returned to the team. This is a hypothetical scenario, not a Deriv-reported baseline.

---

## How to Run

```bash
# Install
pip install -r requirements.txt

# Demo (no API key needed)
python demo.py --scenario ALL
python demo.py --scenario WASH-001 --verbose

# With Claude API (richer reasoning)
ANTHROPIC_API_KEY=your_key python demo.py --scenario ALL

# REST API
python api.py
# → http://localhost:8000/docs  (Swagger UI)
# → GET  /scenarios
# → POST /investigate/WASH-001
# → POST /investigate/ATO-001
```

---

## Files

```
deriv-fraud-copilot/
├── agents/
│   ├── signal_agent.py      # S1.0: 9 deterministic fraud rules
│   ├── pattern_agent.py     # S2.0: statistical anomaly detection
│   ├── policy_agent.py      # S2.5: TF-IDF RAG over AML policies
│   ├── reasoning_agent.py   # S3.0: Claude API verdict synthesis
│   └── orchestrator.py      # LangGraph StateGraph + sequential fallback
├── tools/
│   └── deriv_api.py         # Deriv WebSocket API client + synthetic fallback
├── data/
│   └── synthetic_scenarios.py  # 5 fraud scenarios (Deriv API shape)
├── api.py                   # FastAPI server
├── demo.py                  # CLI demo with color output
└── ARCHITECTURE.md          # This document
```

---

## Interview Cheat Sheet

**"What problem does this solve?"**
Deriv investigates fraud manually. 168M deals/month. This automates the investigation pipeline.

**"Why three agents instead of one?"**
Separation of concerns. S1.0 is auditable to compliance. S2.0 is interpretable to data science. S3.0 synthesises for the investigator. Each layer is independently testable.

**"Why LangGraph?"**
State machine with checkpointing and native human-in-the-loop. Same architecture Deriv already uses in their QA Loop. The human gate is a first-class node, not bolted on.

**"How does it connect to Deriv's existing stack?"**
Each component was chosen to reduce integration friction with what Deriv has already deployed: Weaviate for vector storage, Claude API for reasoning, FastAPI for the backend. The architecture is the IP — the vendor choices are swappable. What matters is the three-layer pipeline, the escalation logic, and the audit trail.

**"What would you build next?"**
FRL-System CoLES embeddings replace Pattern Agent's Z-score. Self-supervised — no labels needed. Already trained architecture, just needs Deriv's data. GraphSAGE adds network-level ring detection.

**"How does this scale to 168M monthly deals?"**
Deterministic rules (S1.0) run in microseconds. Pattern agent is pure numpy — sub-millisecond. Only CRITICAL/HIGH risk cases hit the LLM. With prompt caching (Osama's team already at 85.8% hit rate), marginal cost per investigation is very low.

**"What's the real IP?"**
Rakshit's words: "Real IP is in the structure and the data, not the model." The structure here is the three-layer pipeline + the escalation logic + the audit trail. That's what survives if you swap Claude for GPT-5.
