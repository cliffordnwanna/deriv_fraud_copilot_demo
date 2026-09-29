"""
Orchestrator — LangGraph StateGraph
Coordinates the full fraud investigation pipeline:

  INPUT
    │
    ▼
  [Signal Agent]   ← deterministic rules (Software 1.0)
    │
    ▼
  [Pattern Agent]  ← statistical anomaly detection (Software 2.0)
    │
    ▼
  [Policy Agent]   ← RAG over AML/fraud policies
    │
    ▼
  [Reasoning Agent] ← Claude synthesises → structured verdict (Software 3.0)
    │
    ▼
  [Human Gate]     ← risk-tiered approval (auto / review / escalate / block)
    │
    ▼
  OUTPUT + AUDIT TRAIL

LangGraph gives us explicit stateful workflow routing. Persistence/checkpointing and a
true interrupt/resume approval flow would be added with a production checkpointer and
case-management integration; this demo records the human-gate state without executing actions.
"""
from __future__ import annotations
import json
import os
import uuid
from datetime import datetime
from typing import Any, TypedDict

# ── State definition ──────────────────────────────────────────────────────────

class FraudState(TypedDict, total=False):
    # Input
    investigation_id: str
    account_id: str
    scenario_data: dict

    # Agent outputs
    signal_result: dict
    pattern_result: dict
    policy_result: dict
    reasoning_result: dict

    # Control
    current_step: str
    error: str | None

    # Final
    verdict: str
    human_decision: str | None
    audit_trail: list[dict]


# ── LangGraph node functions ───────────────────────────────────────────────────

def node_signal_analysis(state: FraudState) -> FraudState:
    """Run deterministic fraud rules."""
    from agents.signal_agent import run_signal_agent
    try:
        result = run_signal_agent(state["scenario_data"])
        return {**state, "signal_result": result.to_dict(), "current_step": "pattern_analysis"}
    except Exception as e:
        return {**state, "error": f"Signal agent failed: {e}", "current_step": "error"}


def node_pattern_analysis(state: FraudState) -> FraudState:
    """Run statistical anomaly detection."""
    from agents.pattern_agent import run_pattern_agent
    try:
        result = run_pattern_agent(state["scenario_data"])
        return {**state, "pattern_result": result.to_dict(), "current_step": "policy_lookup"}
    except Exception as e:
        return {**state, "error": f"Pattern agent failed: {e}", "current_step": "error"}


def node_policy_lookup(state: FraudState) -> FraudState:
    """RAG policy retrieval."""
    from agents.policy_agent import run_policy_agent
    try:
        signal_result = state.get("signal_result", {})
        pattern_result = state.get("pattern_result", {})
        result = run_policy_agent(
            signals=signal_result.get("signals", []),
            risk_tier=signal_result.get("risk_tier", "LOW"),
            account_data=state["scenario_data"].get("account", {}),
            patterns=pattern_result.get("patterns", []),
        )
        return {**state, "policy_result": result.to_dict(), "current_step": "reasoning"}
    except Exception as e:
        # Policy agent failure is non-fatal — continue with empty context
        return {
            **state,
            "policy_result": {
                "matches": [],
                "policy_context": "Policy retrieval unavailable. Applying default escalation matrix.",
                "recommended_action": "Manual compliance review required.",
                "applicable_regulations": ["FATF Recommendations"],
            },
            "current_step": "reasoning",
        }


def node_reasoning(state: FraudState) -> FraudState:
    """Claude synthesises verdict."""
    from agents.reasoning_agent import run_reasoning_agent
    try:
        account = state["scenario_data"].get("account") or state["scenario_data"].get("accounts", [{}])[0]
        result = run_reasoning_agent(
            account_id=state["account_id"],
            signal_result=state.get("signal_result", {}),
            pattern_result=state.get("pattern_result", {}),
            policy_result=state.get("policy_result", {}),
            account_data=account,
        )
        return {
            **state,
            "reasoning_result": result.to_dict(),
            "verdict": result.verdict,
            "current_step": "human_gate",
        }
    except Exception as e:
        return {**state, "error": f"Reasoning agent failed: {e}", "current_step": "error"}


def node_human_gate(state: FraudState) -> FraudState:
    """
    Risk-tiered human approval gate.
    In production: integrates with Slack/email/case-management approval workflow.
    Demo mode records the required human decision state; it does not execute
    consequential account restrictions or SAR filings.
    """
    verdict = state.get("verdict", "REVIEW")
    reasoning = state.get("reasoning_result", {})

    human_required = reasoning.get("human_review_required", False)

    if verdict == "CLEAR":
        human_decision = "APPROVED — NO ACTION REQUIRED"
        final_action = "No action. Continue with enhanced monitoring."
    elif verdict == "REVIEW":
        human_decision = "AWAITING_COMPLIANCE_REVIEW"
        final_action = "Case queued for compliance team review within 48h. Restrict new payment methods."
    elif verdict == "ESCALATE":
        human_decision = "AWAITING_SENIOR_OFFICER_DECISION"
        final_action = "AI recommends: withdrawal hold + source-of-funds request. Pending human approval."
    else:  # BLOCK
        human_decision = "AWAITING_HUMAN_CONFIRMATION"
        final_action = "AI recommends: temporary restriction + SAR filing. Pending compliance officer approval."

    return {
        **state,
        "human_decision": human_decision,
        "current_step": "complete",
        "reasoning_result": {
            **reasoning,
            "final_action_taken": final_action,
            "human_decision": human_decision,
        },
    }


def node_error_handler(state: FraudState) -> FraudState:
    """Catch and surface errors without crashing the pipeline."""
    return {
        **state,
        "verdict": "REVIEW",
        "human_decision": "ERROR_REQUIRES_MANUAL_REVIEW",
        "current_step": "complete",
    }


# ── Routing logic ─────────────────────────────────────────────────────────────

def route_after_step(state: FraudState) -> str:
    step = state.get("current_step", "error")
    if state.get("error"):
        return "error_handler"
    return {
        "pattern_analysis": "pattern_analysis",
        "policy_lookup":    "policy_lookup",
        "reasoning":        "reasoning",
        "human_gate":       "human_gate",
        "complete":         "__end__",
        "error":            "error_handler",
    }.get(step, "error_handler")


# ── Graph construction ────────────────────────────────────────────────────────

def build_graph():
    """Build and return the compiled LangGraph investigation graph."""
    try:
        from langgraph.graph import StateGraph, END

        builder = StateGraph(FraudState)

        builder.add_node("signal_analysis",  node_signal_analysis)
        builder.add_node("pattern_analysis", node_pattern_analysis)
        builder.add_node("policy_lookup",    node_policy_lookup)
        builder.add_node("reasoning",        node_reasoning)
        builder.add_node("human_gate",       node_human_gate)
        builder.add_node("error_handler",    node_error_handler)

        builder.set_entry_point("signal_analysis")

        for node in ["signal_analysis", "pattern_analysis", "policy_lookup", "reasoning", "human_gate"]:
            builder.add_conditional_edges(node, route_after_step)

        builder.add_edge("error_handler", END)

        return builder.compile()

    except ImportError:
        return None  # fallback to sequential runner


# ── Sequential fallback (no langgraph dependency) ─────────────────────────────

def run_sequential(initial_state: FraudState) -> FraudState:
    """Run the pipeline sequentially without LangGraph (for environments without it)."""
    state = initial_state
    steps = [
        node_signal_analysis,
        node_pattern_analysis,
        node_policy_lookup,
        node_reasoning,
        node_human_gate,
    ]
    for step in steps:
        if state.get("error"):
            state = node_error_handler(state)
            break
        state = step(state)
    return state


# ── Audit trail builder ───────────────────────────────────────────────────────

def build_audit_trail(final_state: FraudState) -> list[dict]:
    now = datetime.utcnow().isoformat()
    return [
        {
            "step": "signal_analysis",
            "timestamp": now,
            "output_summary": {
                "risk_tier": final_state.get("signal_result", {}).get("risk_tier"),
                "rules_triggered": final_state.get("signal_result", {}).get("triggered_rules"),
                "risk_score": final_state.get("signal_result", {}).get("risk_score"),
            },
        },
        {
            "step": "pattern_analysis",
            "timestamp": now,
            "output_summary": {
                "anomaly_score": final_state.get("pattern_result", {}).get("anomaly_score"),
                "patterns_detected": [p["pattern_id"] for p in final_state.get("pattern_result", {}).get("patterns", [])],
            },
        },
        {
            "step": "policy_lookup",
            "timestamp": now,
            "output_summary": {
                "policies_retrieved": [m["policy_id"] for m in final_state.get("policy_result", {}).get("matches", [])],
                "recommended_action": final_state.get("policy_result", {}).get("recommended_action"),
            },
        },
        {
            "step": "reasoning",
            "timestamp": now,
            "output_summary": {
                "verdict": final_state.get("reasoning_result", {}).get("verdict"),
                "confidence": final_state.get("reasoning_result", {}).get("confidence"),
                "model_used": final_state.get("reasoning_result", {}).get("model_used"),
                "sar_required": final_state.get("reasoning_result", {}).get("sar_required"),
            },
        },
        {
            "step": "human_gate",
            "timestamp": now,
            "output_summary": {
                "human_decision": final_state.get("human_decision"),
                "final_action": final_state.get("reasoning_result", {}).get("final_action_taken"),
            },
        },
    ]


# ── Main public API ───────────────────────────────────────────────────────────

def investigate(scenario_data: dict) -> dict:
    """
    Run a complete fraud investigation and return the full result.
    Entry point for FastAPI and demo script.
    """
    investigation_id = str(uuid.uuid4())[:8].upper()
    account_id = (
        scenario_data.get("account", {}).get("loginid")
        or scenario_data.get("scenario_id", "UNKNOWN")
    )

    initial_state: FraudState = {
        "investigation_id": investigation_id,
        "account_id": account_id,
        "scenario_data": scenario_data,
        "current_step": "pattern_analysis",  # first node sets this correctly
        "audit_trail": [],
        "error": None,
    }

    graph = build_graph()
    if graph is not None:
        final_state = graph.invoke(initial_state)
    else:
        final_state = run_sequential(initial_state)

    audit = build_audit_trail(final_state)

    return {
        "investigation_id": investigation_id,
        "account_id": account_id,
        "verdict": final_state.get("verdict", "REVIEW"),
        "human_decision": final_state.get("human_decision"),
        "signal_analysis": final_state.get("signal_result", {}),
        "pattern_analysis": final_state.get("pattern_result", {}),
        "policy_context": {
            "policies_retrieved": [m["policy_id"] for m in final_state.get("policy_result", {}).get("matches", [])],
            "recommended_action": final_state.get("policy_result", {}).get("recommended_action"),
        },
        "reasoning": final_state.get("reasoning_result", {}),
        "audit_trail": audit,
        "error": final_state.get("error"),
    }
