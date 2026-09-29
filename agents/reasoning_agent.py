"""
Reasoning Agent — OpenAI API (Software 3.0 / Agentic layer)
Synthesises signal, pattern, and policy evidence into a structured
investigation verdict with natural-language justification.

Design choices:
- Structured output enforced via JSON schema in system prompt
- Retry on parse failure (same pattern Deriv uses in Site Sense / QA Loop)
- Separate system prompt from user turn (enables prompt caching — Deriv
  achieves 85.8% cache hit rate this way)
- Output is auditable: every field traceable to a specific agent's output
"""
from __future__ import annotations
import json
import os
from dataclasses import dataclass, field
from typing import Any, Literal


# ── Output schema ─────────────────────────────────────────────────────────────

@dataclass
class InvestigationVerdict:
    account_id: str
    verdict: Literal["CLEAR", "REVIEW", "ESCALATE", "BLOCK"]
    confidence: float                          # 0.0–1.0
    risk_score: float                          # composite
    primary_concern: str                       # one sentence
    detailed_reasoning: str                    # full narrative
    recommended_action: str                    # specific next step
    policy_citations: list[str]                # which policies apply
    evidence_summary: list[str]                # bullet points
    human_review_required: bool
    sar_required: bool                         # file suspicious activity report
    model_used: str = "gpt-4o-mini"
    reasoning_tokens: int = 0
    parse_retries: int = 0

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 4),
            "risk_score": round(self.risk_score, 4),
            "primary_concern": self.primary_concern,
            "detailed_reasoning": self.detailed_reasoning,
            "recommended_action": self.recommended_action,
            "policy_citations": self.policy_citations,
            "evidence_summary": self.evidence_summary,
            "human_review_required": self.human_review_required,
            "sar_required": self.sar_required,
            "model_used": self.model_used,
            "reasoning_tokens": self.reasoning_tokens,
            "parse_retries": self.parse_retries,
        }


# ── System prompt (cacheable — does not change between cases) ─────────────────

SYSTEM_PROMPT = """You are the Reasoning Agent in Deriv's Fraud Investigation Copilot.
Your role: synthesise fraud signals, statistical patterns, and AML policy context
into a structured investigation verdict.

You will receive:
1. Signal agent output: deterministic rule violations with severity
2. Pattern agent output: statistical anomaly scores from transaction sequence analysis
3. Policy agent output: relevant AML/fraud policy excerpts and recommended escalation tier
4. Account profile: basic account metadata

CRITICAL OUTPUT RULES:
- Respond ONLY with valid JSON. No prose before or after.
- Use the exact schema below. Missing fields will be rejected.
- Evidence must be specific (cite rule IDs, amounts, percentages). Never vague.
- Do NOT recommend actions outside the escalation matrix. Follow policy.
- If signals conflict (e.g. high anomaly score but signals explain it as normal),
  explain the conflict and favour the more conservative interpretation.

OUTPUT SCHEMA:
{
  "verdict": "CLEAR | REVIEW | ESCALATE | BLOCK",
  "confidence": <float 0.0-1.0>,
  "risk_score": <float 0.0-1.0, composite>,
  "primary_concern": "<one sentence: the single biggest fraud concern>",
  "detailed_reasoning": "<2-4 sentences: how signals + patterns + policy combine>",
  "recommended_action": "<specific next step from policy escalation matrix>",
  "policy_citations": ["<policy ID 1>", "<policy ID 2>"],
  "evidence_summary": ["<bullet 1>", "<bullet 2>", "<bullet 3>"],
  "human_review_required": <true|false>,
  "sar_required": <true|false>
}

VERDICT MAPPING (follow strictly):
- CLEAR: No signals triggered, anomaly_score < 0.2. Normal activity.
- REVIEW: 1-2 low/medium signals OR anomaly_score 0.2-0.4. Compliance review needed.
- ESCALATE: High signals OR anomaly_score 0.4-0.7 OR wash/mule pattern. Senior review + hold.
- BLOCK: Critical signals (ATO/wash/mule ring confirmed) OR anomaly_score > 0.7. Immediate restriction + SAR.

SAR is required when: BLOCK verdict, or wash/ATO/mule pattern confirmed, or CRITICAL severity signal.
"""


# ── User turn constructor ─────────────────────────────────────────────────────

def _build_user_turn(
    account_id: str,
    signal_result: dict,
    pattern_result: dict,
    policy_result: dict,
    account_data: dict,
) -> str:
    return f"""FRAUD INVESTIGATION CASE: {account_id}

=== SIGNAL AGENT OUTPUT (Deterministic Rules) ===
Risk Tier: {signal_result.get('risk_tier')}
Risk Score: {signal_result.get('risk_score')}
Triggered Rules ({len(signal_result.get('triggered_rules', []))}):
{json.dumps(signal_result.get('signals', []), indent=2)}

=== PATTERN AGENT OUTPUT (Statistical Analysis) ===
Anomaly Score: {pattern_result.get('anomaly_score')}
Detected Patterns:
{json.dumps(pattern_result.get('patterns', []), indent=2)}
Temporal Features:
{json.dumps(pattern_result.get('temporal_features', {}), indent=2)}

=== POLICY AGENT OUTPUT (RAG) ===
Recommended Action: {policy_result.get('recommended_action')}
Applicable Regulations: {policy_result.get('applicable_regulations')}
Policy Context:
{policy_result.get('policy_context', '')[:1500]}

=== ACCOUNT PROFILE ===
{json.dumps(account_data, indent=2)}

Produce your structured JSON verdict now."""


# ── Claude API call with retry ────────────────────────────────────────────────

def _call_openai(system: str, user: str, api_key: str, model: str) -> tuple[str, int]:
    """Call OpenAI API. Returns (raw_text, input_tokens)."""
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return response.choices[0].message.content, response.usage.prompt_tokens
    except ImportError:
        raise RuntimeError("openai package not installed. Run: pip install openai")


def _parse_verdict(raw: str) -> dict:
    """Extract JSON from Claude response. Handles markdown code fences."""
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    return json.loads(raw)


def _mock_verdict(
    account_id: str,
    signal_result: dict,
    pattern_result: dict,
) -> dict:
    """
    Deterministic fallback when no API key is set.
    Produces a plausible verdict purely from signal/pattern data.
    Used for demos without an API key.
    """
    risk_tier = signal_result.get("risk_tier", "LOW")
    anomaly = pattern_result.get("anomaly_score", 0.0)
    signals = signal_result.get("signals", [])
    composite = min(1.0, signal_result.get("risk_score", 0.0) * 0.7 + anomaly * 0.3)

    verdict_map = {
        "CRITICAL": "BLOCK",
        "HIGH": "ESCALATE",
        "MEDIUM": "REVIEW",
        "LOW": "CLEAR",
    }
    verdict = verdict_map.get(risk_tier, "REVIEW")

    # Override if anomaly score is very high
    if anomaly >= 0.7 and verdict not in ("BLOCK", "ESCALATE"):
        verdict = "ESCALATE"

    critical_signals = [s for s in signals if s.get("severity") == "CRITICAL"]
    sar_required = verdict == "BLOCK" or bool(critical_signals)

    primary_concern = (
        signals[0]["description"] if signals
        else "No specific rule violations. Statistical patterns flagged."
    )

    return {
        "verdict": verdict,
        "confidence": round(min(0.95, composite + 0.15), 4),
        "risk_score": round(composite, 4),
        "primary_concern": primary_concern,
        "detailed_reasoning": (
            f"Deterministic rules flagged {len(signals)} signal(s) with composite risk score "
            f"{signal_result.get('risk_score', 0):.2f}. Statistical analysis detected anomaly "
            f"score {anomaly:.2f}. Combined assessment: {risk_tier} risk tier. "
            f"[Note: Generated by deterministic fallback — no LLM API key configured.]"
        ),
        "recommended_action": {
            "BLOCK": "Immediate account restriction. File SAR with FIU within 24 hours.",
            "ESCALATE": "Place withdrawal hold. Senior compliance review within 24 hours.",
            "REVIEW": "Compliance team review within 48 hours. Restrict new payment methods.",
            "CLEAR": "Continue normal monitoring. No action required.",
        }.get(verdict, "Manual review required."),
        "policy_citations": ["FATF_REC10_CDD", "FRAUD_ESCALATION_MATRIX"],
        "evidence_summary": [s["description"] for s in signals[:3]],
        "human_review_required": verdict in ("ESCALATE", "BLOCK"),
        "sar_required": sar_required,
    }


# ── Main entry ────────────────────────────────────────────────────────────────

def run_reasoning_agent(
    account_id: str,
    signal_result: dict,
    pattern_result: dict,
    policy_result: dict,
    account_data: dict,
    api_key: str | None = None,
    model: str | None = None,
    max_retries: int = 2,
) -> InvestigationVerdict:
    """
    Synthesise all agent outputs into a final investigation verdict.
    Falls back to deterministic verdict if no API key is provided.
    """
    resolved_key = api_key or os.environ.get("OPENAI_API_KEY")
    model = model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    retries = 0

    if not resolved_key:
        # Demo mode: deterministic fallback
        raw_verdict = _mock_verdict(account_id, signal_result, pattern_result)
        return InvestigationVerdict(
            account_id=account_id,
            model_used="deterministic-fallback",
            reasoning_tokens=0,
            parse_retries=0,
            **raw_verdict,
        )

    user_turn = _build_user_turn(
        account_id=account_id,
        signal_result=signal_result,
        pattern_result=pattern_result,
        policy_result=policy_result,
        account_data=account_data,
    )

    last_error = None
    while retries <= max_retries:
        try:
            raw, tokens = _call_openai(SYSTEM_PROMPT, user_turn, resolved_key, model)
            parsed = _parse_verdict(raw)
            return InvestigationVerdict(
                account_id=account_id,
                model_used=model,
                reasoning_tokens=tokens,
                parse_retries=retries,
                **parsed,
            )
        except json.JSONDecodeError as e:
            last_error = e
            retries += 1
            # On retry: add stricter instruction (Site Sense pattern)
            user_turn += "\n\nPREVIOUS RESPONSE WAS NOT VALID JSON. Respond with ONLY the JSON object. No markdown, no prose."
        except Exception as e:
            # Non-JSON error (API, auth, etc.) — fall back to deterministic
            raw_verdict = _mock_verdict(account_id, signal_result, pattern_result)
            return InvestigationVerdict(
                account_id=account_id,
                model_used=f"deterministic-fallback (error: {type(e).__name__})",
                reasoning_tokens=0,
                parse_retries=retries,
                **raw_verdict,
            )

    # Exhausted retries
    raw_verdict = _mock_verdict(account_id, signal_result, pattern_result)
    return InvestigationVerdict(
        account_id=account_id,
        model_used=f"deterministic-fallback (json-parse-failure after {max_retries} retries)",
        reasoning_tokens=0,
        parse_retries=retries,
        **raw_verdict,
    )
