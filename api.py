"""
FastAPI server — Deriv Fraud Investigation Copilot
Exposes the investigation pipeline as a REST API.

Endpoints:
  GET  /health                        — health check
  GET  /scenarios                     — list demo scenarios
  POST /investigate/{scenario_id}     — run a full investigation
  POST /investigate/custom            — investigate arbitrary account data
  GET  /investigation/{id}            — retrieve investigation by ID (in-memory for demo)
"""
from __future__ import annotations
import os
from datetime import datetime
from typing import Any
import hashlib
import hmac
import time
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="Deriv Fraud Investigation Copilot",
    description=(
        "Multi-agent fraud investigation system combining deterministic rules (Software 1.0), "
        "statistical anomaly detection (Software 2.0), and LLM reasoning (Software 3.0). "
        "Orchestrated via LangGraph with human-in-the-loop escalation gates."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for demo
_investigations: dict[str, dict] = {}
BASE_DIR = Path(__file__).resolve().parent


def _verify_slack_signature(request: Request, body: bytes) -> bool:
    """Verify Slack signing secret when configured; otherwise allow demo/local use."""
    secret = os.getenv("SLACK_SIGNING_SECRET")
    if not secret:
        return True
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs(time.time() - ts) > 300:
        return False
    base = f"v0:{timestamp}:".encode() + body
    expected = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _slack_blocks(result: dict, scenario_id: str) -> list[dict]:
    reasoning = result.get("reasoning", {})
    evidence = reasoning.get("evidence_summary") or ["No high-confidence evidence summary returned."]
    evidence_text = "\n".join(f"• {e}" for e in evidence[:6])
    classification = result.get("risk_classification", result.get("verdict", "REVIEW"))
    recommendation = result.get("ai_recommendation", "Manual review required.")
    return [
        {"type": "header", "text": {"type": "plain_text", "text": f"🔍 Fraud Investigation — {scenario_id}"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Risk Score*\n{round((result.get('signal_analysis', {}).get('risk_score', 0) * .6 + result.get('pattern_analysis', {}).get('anomaly_score', 0) * .4) * 100)}/100"},
            {"type": "mrkdwn", "text": f"*Classification*\n{classification}"},
        ]},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Evidence*\n{evidence_text}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*AI Recommendation*\n{recommendation}\n\n_AI advises — human decides._"}},
        {"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "Approve"}, "style": "primary", "action_id": "approve", "value": scenario_id},
            {"type": "button", "text": {"type": "plain_text", "text": "Reject"}, "style": "danger", "action_id": "reject", "value": scenario_id},
            {"type": "button", "text": {"type": "plain_text", "text": "Request Evidence"}, "action_id": "request_evidence", "value": scenario_id},
        ]},
    ]


# ── Models ────────────────────────────────────────────────────────────────────

class InvestigationResponse(BaseModel):
    investigation_id: str
    account_id: str
    verdict: str
    risk_classification: str
    ai_recommendation: str
    human_decision_required: bool
    human_decision: str | None
    signal_analysis: dict
    pattern_analysis: dict
    policy_context: dict
    reasoning: dict
    audit_trail: list[dict]
    error: str | None
    timestamp: str
    data_source: str = "synthetic"


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
def ui():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.post("/slack/command")
async def slack_command(request: Request):
    body = await request.body()
    if not _verify_slack_signature(request, body):
        raise HTTPException(status_code=401, detail="Invalid Slack signature")
    fields = parse_qs(body.decode("utf-8"))
    scenario_id = (fields.get("text", [""])[0] or "MULE-001").strip().upper()
    from data.synthetic_scenarios import ALL_SCENARIOS, get_scenario
    from agents.orchestrator import investigate
    if scenario_id not in ALL_SCENARIOS:
        return JSONResponse({"response_type": "ephemeral", "text": f"Unknown scenario `{scenario_id}`. Available: {', '.join(ALL_SCENARIOS)}"})
    result = investigate(get_scenario(scenario_id))
    reasoning = result.get("reasoning", {})
    result["risk_classification"] = {
        "CLEAR": "NORMAL ACTIVITY", "REVIEW": "SUSPICIOUS — REVIEW FLAGGED",
        "ESCALATE": "HIGH RISK — INVESTIGATION REQUIRED", "BLOCK": "CRITICAL RISK — ACTION REQUIRED",
    }.get(result.get("verdict", "REVIEW"), "UNKNOWN")
    result["ai_recommendation"] = reasoning.get("recommended_action", "Manual review required.")
    return JSONResponse({"response_type": "in_channel", "blocks": _slack_blocks(result, scenario_id)})


@app.post("/slack/interactions")
async def slack_interactions(request: Request):
    body = await request.body()
    if not _verify_slack_signature(request, body):
        raise HTTPException(status_code=401, detail="Invalid Slack signature")
    fields = parse_qs(body.decode("utf-8"))
    return JSONResponse({"response_type": "ephemeral", "text": "Human decision recorded for demonstration mode. No account restriction, withdrawal action, or SAR filing was executed."})


@app.get("/health")
def health():
    try:
        import langgraph  # noqa: F401
        orchestrator = "LangGraph StateGraph"
    except ImportError:
        orchestrator = "Sequential fallback (LangGraph unavailable)"
    return {
        "status": "healthy",
        "service": "Deriv Fraud Investigation Copilot",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "agents": ["signal_agent", "pattern_agent", "policy_agent", "reasoning_agent"],
        "orchestrator": orchestrator,
        "llm": "OpenAI via reasoning_agent; deterministic fallback available",
        "vector_store": "OpenAI embeddings RAG (keyword-overlap fallback if no API key)",
        "data_mode": "synthetic scenarios unless an authenticated integration is explicitly configured",
        "openai_configured": bool(os.getenv("OPENAI_API_KEY")),
        "deriv_configured": bool(os.getenv("DERIV_API_TOKEN")),
        "slack_configured": bool(os.getenv("SLACK_SIGNING_SECRET")),
        "telegram_configured": bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID")),
    }


@app.get("/live/account")
def live_account():
    from tools.deriv_live import get_live_account
    result = get_live_account()
    if result is None:
        return {"configured": False, "message": "DERIV_API_TOKEN not set"}
    return {"configured": True, **result}


@app.get("/scenarios")
def list_scenarios():
    from data.synthetic_scenarios import list_scenarios
    return {"scenarios": list_scenarios()}


@app.get("/accounts")
def accounts_list(limit: int = 100):
    from tools.data_connector import list_accounts
    if not os.path.exists(os.path.join(BASE_DIR, "data", "fraud_cases.db")):
        return {"accounts": [], "count": 0, "data_source": "unavailable",
                 "message": "Run 'python data/generate_dataset.py' to generate the dataset."}
    return list_accounts(limit=limit)


@app.post("/investigate/{scenario_id}", response_model=InvestigationResponse)
def investigate_scenario(scenario_id: str):
    from data.synthetic_scenarios import get_scenario, ALL_SCENARIOS
    from agents.orchestrator import investigate

    if scenario_id in ALL_SCENARIOS:
        scenario_data = get_scenario(scenario_id)
        data_source = "synthetic"
    else:
        from tools.data_normalizer import build_scenario_data
        try:
            scenario_data = build_scenario_data(scenario_id)
        except ValueError:
            raise HTTPException(
                status_code=404,
                detail=f"'{scenario_id}' is not a known synthetic scenario or account ID. "
                       f"Available scenarios: {list(ALL_SCENARIOS.keys())}",
            )
        data_source = scenario_data.get("data_source", "sqlite")

    result = investigate(scenario_data)
    result["timestamp"] = datetime.utcnow().isoformat()
    result["data_source"] = data_source

    _investigations[result["investigation_id"]] = result
    reasoning = result.get("reasoning", {})
    verdict = result.get("verdict", "REVIEW")
    classification_map = {
        "CLEAR": "NORMAL ACTIVITY",
        "REVIEW": "SUSPICIOUS — REVIEW FLAGGED",
        "ESCALATE": "HIGH RISK — INVESTIGATION REQUIRED",
        "BLOCK": "CRITICAL RISK — ACTION REQUIRED",
    }
    result["risk_classification"] = classification_map.get(verdict, "UNKNOWN")
    result["ai_recommendation"] = reasoning.get("recommended_action", "Manual review required.")
    result["human_decision_required"] = bool(reasoning.get("human_review_required", verdict != "CLEAR"))

    from tools.telegram_notifier import notify_if_high_risk
    notify_if_high_risk(result)

    return InvestigationResponse(**result)


@app.post("/investigate/custom", response_model=InvestigationResponse)
def investigate_custom(scenario_data: dict):
    from agents.orchestrator import investigate
    result = investigate(scenario_data)
    result["timestamp"] = datetime.utcnow().isoformat()
    _investigations[result["investigation_id"]] = result
    reasoning = result.get("reasoning", {})
    verdict = result.get("verdict", "REVIEW")
    classification_map = {
        "CLEAR": "NORMAL ACTIVITY",
        "REVIEW": "SUSPICIOUS — REVIEW FLAGGED",
        "ESCALATE": "HIGH RISK — INVESTIGATION REQUIRED",
        "BLOCK": "CRITICAL RISK — ACTION REQUIRED",
    }
    result["risk_classification"] = classification_map.get(verdict, "UNKNOWN")
    result["ai_recommendation"] = reasoning.get("recommended_action", "Manual review required.")
    result["human_decision_required"] = bool(reasoning.get("human_review_required", verdict != "CLEAR"))
    return InvestigationResponse(**result)


@app.get("/investigation/{investigation_id}")
def get_investigation(investigation_id: str):
    if investigation_id not in _investigations:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return _investigations[investigation_id]


@app.get("/investigations")
def list_investigations():
    return {
        "count": len(_investigations),
        "investigations": [
            {
                "id": v["investigation_id"],
                "account_id": v["account_id"],
                "verdict": v["verdict"],
                "timestamp": v.get("timestamp"),
            }
            for v in _investigations.values()
        ],
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
