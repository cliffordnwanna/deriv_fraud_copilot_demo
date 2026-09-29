"""
Policy Agent (S3.0) — embedding-based RAG over a real AML/CFT policy library.

Sources loaded into the corpus:
- FATF 40 Recommendations (R1, R10, R12, R16, R20)
- FATF Virtual Assets Red Flag Indicators Report (2020)
- FFIEC BSA/AML Examination Manual, Appendix F
- FinCEN SAR Filing Obligations (Bank Secrecy Act)
- FinCEN Structuring Advisory (31 U.S.C. §5324)
- FinCEN Transaction Monitoring (AML Rule for RIAs, 2025)
- OFAC SDN Sanctions Compliance Framework (2019)
- Wolfsberg Group AML Principles (2012)
- EU 5AMLD / MiFID II — Trading Platform Obligations
- AML Wash Trading / Market Manipulation indicators

Retrieval uses OpenAI embeddings (cosine similarity) when OPENAI_API_KEY is
configured, so semantically related policies match even without shared
vocabulary (e.g. "account hacked" retrieving an ATO red-flag policy that
never uses the word "hacked"). Falls back to deterministic keyword overlap
scoring — not TF-IDF term-matching — when no key is configured, so the
policy agent never silently fails or requires the LLM to invent citations.

Usage:
    from agents.policy_agent import run_policy_agent
    result = run_policy_agent(signals, risk_tier, account_data, patterns=...)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Policy library path — looks next to this file, then next to data/
# ---------------------------------------------------------------------------
_HERE = Path(__file__).parent
_POLICY_LIB_PATHS = [
    _HERE.parent / "data" / "policy_library.json",
    _HERE / ".." / "data" / "policy_library.json",
    Path("data/policy_library.json"),
    Path("policy_library.json"),
]

_EMBED_MODEL = "text-embedding-3-small"


def _load_policy_library() -> list[dict]:
    """Load policy_library.json from the first path that exists."""
    for p in _POLICY_LIB_PATHS:
        if p.exists():
            with open(p, encoding="utf-8") as f:
                return json.load(f)
    raise FileNotFoundError(
        "policy_library.json not found. Run from the project root or place the file in data/."
    )


# ---------------------------------------------------------------------------
# Embedding-based retrieval
# ---------------------------------------------------------------------------

def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = sum(x * x for x in a) ** 0.5
    mag_b = sum(y * y for y in b) ** 0.5
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def _embed(texts: list[str], api_key: str) -> list[list[float]]:
    from openai import OpenAI
    client = OpenAI(api_key=api_key)
    resp = client.embeddings.create(model=_EMBED_MODEL, input=texts)
    return [d.embedding for d in resp.data]


# ---------------------------------------------------------------------------
# Deterministic keyword-overlap fallback (used when no OPENAI_API_KEY)
# ---------------------------------------------------------------------------

def _tokenise(text: str) -> set[str]:
    import re
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    return {t for t in text.split() if len(t) > 2}


def _keyword_overlap_scores(query: str, docs: list[dict]) -> list[tuple[str, float]]:
    q_tokens = _tokenise(query)
    scores = []
    for doc in docs:
        doc_tokens = _tokenise(doc["title"] + " " + doc["text"])
        overlap = len(q_tokens & doc_tokens)
        score = overlap / max(len(q_tokens), 1)
        scores.append((doc["policy_id"], score))
    return scores


# ---------------------------------------------------------------------------
# Signal-to-query mapper
# Converts structured signal/pattern output into a natural-language query.
# ---------------------------------------------------------------------------

def _build_query(signals: list[dict], risk_tier: str, account_data: dict, patterns: list[dict]) -> str:
    """
    Build a rich natural-language query from the upstream agent outputs.
    signals: list of Signal.to_dict() — {rule_id, severity, description, evidence}
    patterns: list of PatternSignal-shaped dicts — {pattern_id, description, score, evidence}
    """
    parts: list[str] = []

    rule_ids = {s.get("rule_id") for s in signals}
    descriptions = [s.get("description", "") for s in signals]
    pattern_descriptions = [p.get("description", "") for p in (patterns or [])]

    if account_data.get("pep_flag"):
        parts.append("politically exposed person PEP enhanced due diligence senior management approval")
    if account_data.get("sanctions_flag"):
        parts.append("OFAC sanctions SDN list mandatory blocking account freeze reporting")
    if account_data.get("sar_previously_filed"):
        parts.append("SAR suspicious activity report previously filed ongoing monitoring follow-up filing 90 days")

    if "R002_WASH_PATTERN" in rule_ids or "R001_RAPID_WITHDRAWAL" in rule_ids:
        parts.append("withdrawal ratio layering rapid deposit withdrawal cycling placement integration wash-through")
    if "R004_GEO_DEVICE_MISMATCH" in rule_ids:
        parts.append("account takeover ATO brute force login new device foreign IP unauthorised access SAR filing geographic risk")
    if "R005_DEVICE_OVERLAP" in rule_ids:
        parts.append("mule account ring linked device IP shared identifier network money mule SAR filing")
    if "R007_VELOCITY_SPIKE" in rule_ids:
        parts.append("transaction velocity high frequency deposits rapid activity monitoring thresholds")
    if "R006_HIGH_WIN_RATE" in rule_ids:
        parts.append("wash trading market manipulation automated artificial volume anomalous win rate")
    if "R009_ROUND_AMOUNT" in rule_ids or "R003_NEW_ACCOUNT_LARGE_TX" in rule_ids:
        parts.append("structuring deposits below reporting threshold CTR evasion smurfing new account large transaction")
    if "R008_CRYPTO_WITHDRAWAL" in rule_ids:
        parts.append("crypto virtual asset withdrawal payment method change red flag indicators")

    parts.extend(descriptions)
    parts.extend(pattern_descriptions)

    if risk_tier in ("HIGH", "CRITICAL"):
        parts.append("suspicious activity report SAR filing obligation escalation")

    if not parts:
        parts.append("suspicious transaction monitoring AML compliance risk-based approach customer due diligence")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

@dataclass
class PolicyAgentResult:
    matches: list[dict] = field(default_factory=list)
    policy_context: str = ""
    recommended_action: str = ""
    applicable_regulations: list[str] = field(default_factory=list)
    mandatory_actions: list[str] = field(default_factory=list)
    retrieval_method: str = "keyword_overlap"

    def to_dict(self) -> dict:
        return {
            "matches": self.matches,
            "policy_context": self.policy_context,
            "recommended_action": self.recommended_action,
            "applicable_regulations": self.applicable_regulations,
            "mandatory_actions": self.mandatory_actions,
            "retrieval_method": self.retrieval_method,
        }


_RELEVANCE_REASONS = {
    "FATF-R12": "Account is PEP-flagged, requiring senior management approval and enhanced monitoring.",
    "OFAC-1": "Account has a sanctions flag, triggering mandatory OFAC blocking and reporting.",
    "FATF-R20": "Suspicious activity detected; FATF Rec. 20 requires prompt SAR filing to FIU.",
    "FINCEN-SAR-1": "Suspicious activity meets FinCEN SAR threshold; 30-day filing window applies.",
    "FINCEN-SAR-2": "Activity matches SAR categories: account takeover, structuring, or money laundering.",
    "FINCEN-STRUCT-1": "Deposit pattern below reporting threshold indicates structuring under 31 U.S.C. §5324.",
    "FFIEC-RF1": "Deposits below reporting thresholds match FFIEC structuring red flags.",
    "FATF-VA-RF1": "Login/device anomaly pattern matches FATF ATO red flag indicators.",
    "AML-ATO-1": "Combined account-takeover indicators present — critical escalation.",
    "FATF-VA-RF2": "Deposit pattern indicates deliberate structuring.",
    "FATF-VA-RF3": "Shared device/IP across accounts indicates potential mule ring per FATF guidance.",
    "AML-LINKED-1": "Linked accounts require ring investigation; aggregate flows must be assessed.",
    "FATF-VA-RF4": "High withdrawal ratio and rapid cycling indicate layering per FATF guidance.",
    "AML-WITHDRAWAL-1": "Withdrawal ratio triggers escalation protocol.",
    "FATF-VA-RF5": "Geographic shift or foreign payment method from high-risk jurisdiction is a FATF red flag.",
    "AML-GEO-1": "Activity from high-risk/grey-listed jurisdiction requires enhanced review.",
    "FFIEC-RF2": "Account behaviour (velocity, rapid open-deposit-withdraw) matches FFIEC red flags.",
    "FFIEC-RF3": "Transactions involving high-risk jurisdictions match FFIEC geographic red flags.",
    "FFIEC-RF4": "Complex fund movement without business purpose indicates layering.",
    "FINCEN-TM-1": "Transaction velocity or pattern exceeds FinCEN risk-based monitoring thresholds.",
    "AML-VELOCITY-1": "High transaction velocity exceeds population baseline — FATF red flag.",
    "AML-WASH-1": "Rapid trade cycling indicates wash trading / market manipulation.",
    "AML-PEP-1": "PEP or sanctions flag triggers FATF R12 / OFAC mandatory enhanced measures.",
    "AML-KYC-1": "Failed KYC attempts trigger escalation and potential SAR obligation.",
    "AML-CHARGEBACK-1": "Chargeback history indicates card fraud, ATO, or first-party fraud.",
    "FATF-R1": "Risk-based approach requires escalated measures for this risk profile.",
    "FATF-R10": "KYC / CDD obligations apply; failed attempts are a material risk indicator.",
    "FATF-R16": "Wire transfer payment transparency requirements apply to withdrawals.",
    "DERIV-AML-1": "Trading platform AML obligations under 5AMLD/MiFID II apply to this account.",
    "WOLFSBERG-1": "Multiple EDD triggers present; Wolfsberg principles require enhanced review.",
}

_RECOMMENDED_ACTION_BY_TIER = {
    "CRITICAL": "Immediate account restriction. File SAR/STR with FIU within 24 hours. Preserve evidence. Do not alert customer.",
    "HIGH": "Place withdrawal hold. Senior compliance review within 24 hours. Request source of funds.",
    "MEDIUM": "Compliance team review within 48 hours. Restrict new payment methods.",
    "LOW": "Continue normal monitoring. No action required.",
}


def _explain_relevance(policy_id: str) -> str:
    return _RELEVANCE_REASONS.get(policy_id, f"Policy {policy_id} retrieved as contextually relevant to detected signals.")


def _extract_mandatory_actions(policy_id: str, account_data: dict, rule_ids: set[str]) -> list[str]:
    actions = []
    if policy_id == "OFAC-1" and account_data.get("sanctions_flag"):
        actions.append("MANDATORY: Freeze account immediately — OFAC sanctions match. Report to OFAC within 10 business days.")
    if policy_id == "FATF-R12" and account_data.get("pep_flag"):
        actions.append("MANDATORY: Obtain senior management approval before any further account activity. Document source of wealth.")
    if policy_id in ("FINCEN-SAR-1", "FATF-R20") and account_data.get("sar_previously_filed"):
        actions.append("MANDATORY: Prior SAR on file — file follow-up SAR within 90 days of prior filing.")
    if policy_id == "AML-ATO-1" and "R004_GEO_DEVICE_MISMATCH" in rule_ids:
        actions.append("MANDATORY: Suspend withdrawals pending ATO investigation. File SAR within 30 days if confirmed.")
    if policy_id == "FINCEN-STRUCT-1" and "R009_ROUND_AMOUNT" in rule_ids:
        actions.append("MANDATORY: File SAR for suspected structuring (31 U.S.C. §5324). Aggregate all sub-threshold deposits.")
    return actions


class PolicyAgent:
    """S3.0 Policy Agent — retrieves relevant AML/CFT policies via embedding RAG."""

    def __init__(self, api_key: str | None = None):
        self._policies = _load_policy_library()
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self._doc_embeddings: list[list[float]] | None = None
        if self._api_key:
            try:
                texts = [f"{d['title']}. {d['text']}" for d in self._policies]
                self._doc_embeddings = _embed(texts, self._api_key)
            except Exception:
                self._doc_embeddings = None  # fall back to keyword overlap

    def retrieve(self, query: str, top_k: int = 4) -> list[str]:
        if self._doc_embeddings is not None:
            try:
                q_emb = _embed([query], self._api_key)[0]
                scores = [
                    (doc["policy_id"], _cosine(q_emb, emb))
                    for doc, emb in zip(self._policies, self._doc_embeddings)
                ]
                scores.sort(key=lambda x: x[1], reverse=True)
                return [pid for pid, score in scores[:top_k] if score > 0.15], "openai_embeddings"
            except Exception:
                pass
        scores = _keyword_overlap_scores(query, self._policies)
        scores.sort(key=lambda x: x[1], reverse=True)
        return [pid for pid, score in scores[:top_k] if score > 0], "keyword_overlap"


_agent_singleton: PolicyAgent | None = None


def _get_agent() -> PolicyAgent:
    global _agent_singleton
    if _agent_singleton is None:
        _agent_singleton = PolicyAgent()
    return _agent_singleton


def run_policy_agent(
    signals: list[dict],
    risk_tier: str,
    account_data: dict,
    patterns: list[dict] | None = None,
    top_k: int = 4,
) -> PolicyAgentResult:
    """
    Retrieve the top-k most relevant AML policies given signal agent output.

    signals:      list of Signal.to_dict() from agents.signal_agent
    risk_tier:    LOW | MEDIUM | HIGH | CRITICAL
    account_data: the scenario's account dict
    patterns:     optional list of PatternSignal-shaped dicts from agents.pattern_agent
    """
    agent = _get_agent()
    policy_map = {p["policy_id"]: p for p in agent._policies}
    rule_ids = {s.get("rule_id") for s in signals}

    query = _build_query(signals, risk_tier, account_data, patterns or [])
    matched_ids, method = agent.retrieve(query, top_k=top_k)

    matches = []
    mandatory_actions: list[str] = []
    for pid in matched_ids:
        policy = policy_map.get(pid)
        if not policy:
            continue
        matches.append({
            "policy_id": pid,
            "title": policy["title"],
            "category": policy["category"],
            "source": policy["source"],
            "relevance_reason": _explain_relevance(pid),
        })
        mandatory_actions.extend(_extract_mandatory_actions(pid, account_data, rule_ids))

    policy_context = " | ".join(
        f"[{m['policy_id']}] {m['title']}: {m['relevance_reason']}" for m in matches
    ) or "No specific policy matched; default escalation matrix applies."

    return PolicyAgentResult(
        matches=matches,
        policy_context=policy_context,
        recommended_action=_RECOMMENDED_ACTION_BY_TIER.get(risk_tier, "Manual compliance review required."),
        applicable_regulations=[m["policy_id"] for m in matches] or ["FATF Recommendations"],
        mandatory_actions=list(dict.fromkeys(mandatory_actions)),
        retrieval_method=method,
    )
