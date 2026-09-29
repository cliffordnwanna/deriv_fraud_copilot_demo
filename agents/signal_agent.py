"""
Signal Agent — Software 1.0 (deterministic rule engine)
Evaluates raw transaction + account data against hard-coded fraud rules.
No ML, no LLM — pure deterministic logic. Fast, auditable, explainable.

Rules derived from:
- FATF Recommendation 10 (Customer Due Diligence)
- Deriv's public T&Cs (section 10: Fraud prevention)
- Industry AML standards for CFD/binary options platforms
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any


# ── Signal output ─────────────────────────────────────────────────────────────

@dataclass
class Signal:
    rule_id: str
    severity: str          # LOW | MEDIUM | HIGH | CRITICAL
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    triggered: bool = True

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "triggered": self.triggered,
        }


@dataclass
class SignalAgentResult:
    account_id: str
    signals: list[Signal] = field(default_factory=list)
    risk_score: float = 0.0   # 0.0–1.0
    risk_tier: str = "LOW"     # LOW | MEDIUM | HIGH | CRITICAL
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "signals": [s.to_dict() for s in self.signals],
            "risk_score": round(self.risk_score, 4),
            "risk_tier": self.risk_tier,
            "summary": self.summary,
            "triggered_rules": [s.rule_id for s in self.signals if s.triggered],
        }


# ── Rule weights ──────────────────────────────────────────────────────────────
RULE_WEIGHTS = {
    "R001_RAPID_WITHDRAWAL":      0.30,
    "R002_WASH_PATTERN":          0.35,
    "R003_NEW_ACCOUNT_LARGE_TX":  0.25,
    "R004_GEO_DEVICE_MISMATCH":   0.40,
    "R005_DEVICE_OVERLAP":        0.45,
    "R006_HIGH_WIN_RATE":         0.25,
    "R007_VELOCITY_SPIKE":        0.20,
    "R008_CRYPTO_WITHDRAWAL":     0.15,
    "R009_ROUND_AMOUNT":          0.10,
    "R010_DORMANT_BURST":         0.30,
}

SEVERITY_MAP = {
    "R001_RAPID_WITHDRAWAL":      "HIGH",
    "R002_WASH_PATTERN":          "CRITICAL",
    "R003_NEW_ACCOUNT_LARGE_TX":  "HIGH",
    "R004_GEO_DEVICE_MISMATCH":   "CRITICAL",
    "R005_DEVICE_OVERLAP":        "CRITICAL",
    "R006_HIGH_WIN_RATE":         "MEDIUM",
    "R007_VELOCITY_SPIKE":        "MEDIUM",
    "R008_CRYPTO_WITHDRAWAL":     "LOW",
    "R009_ROUND_AMOUNT":          "LOW",
    "R010_DORMANT_BURST":         "HIGH",
}


# ── Rule functions ────────────────────────────────────────────────────────────

def _transactions(data: dict) -> list[dict]:
    return data.get("statement", {}).get("transactions", [])

def _tx_time(tx: dict) -> datetime:
    return datetime.utcfromtimestamp(tx.get("transaction_time", 0))


def rule_rapid_withdrawal(data: dict) -> Signal | None:
    """
    R001: Deposit followed by withdrawal within 48 hours with <5% trading activity.
    Classic money-laundering through platform pattern.
    """
    txns = _transactions(data)
    deposits = [t for t in txns if t["action_type"] == "deposit"]
    withdrawals = [t for t in txns if t["action_type"] == "withdrawal"]

    for dep in deposits:
        dep_time = _tx_time(dep)
        dep_amount = abs(dep["amount"])
        for wd in withdrawals:
            wd_time = _tx_time(wd)
            wd_amount = abs(wd["amount"])
            hours_diff = abs((wd_time - dep_time).total_seconds() / 3600)
            if hours_diff <= 48 and wd_amount >= dep_amount * 0.80:
                # Check if minimal trading between them
                trades = [
                    t for t in txns
                    if t["action_type"] in ("buy", "sell")
                    and min(dep_time, wd_time) <= _tx_time(t) <= max(dep_time, wd_time)
                ]
                traded_volume = sum(abs(t["amount"]) for t in trades)
                if traded_volume < dep_amount * 0.05:
                    return Signal(
                        rule_id="R001_RAPID_WITHDRAWAL",
                        severity=SEVERITY_MAP["R001_RAPID_WITHDRAWAL"],
                        description="Deposit followed by rapid large withdrawal with minimal trading",
                        evidence={
                            "deposit_amount": dep_amount,
                            "withdrawal_amount": wd_amount,
                            "hours_between": round(hours_diff, 1),
                            "trading_ratio": round(traded_volume / dep_amount, 4) if dep_amount else 0,
                        },
                    )
    return None


def rule_wash_pattern(data: dict) -> Signal | None:
    """
    R002: Total withdrawals > 90% of deposits with win_rate > 0 (genuine trading = losses).
    Suggests deposits routed through platform for laundering.
    """
    txns = _transactions(data)
    total_deposited = sum(abs(t["amount"]) for t in txns if t["action_type"] == "deposit")
    total_withdrawn = sum(abs(t["amount"]) for t in txns if t["action_type"] == "withdrawal")

    if total_deposited < 500:
        return None  # below threshold

    wash_ratio = total_withdrawn / total_deposited if total_deposited > 0 else 0
    if wash_ratio >= 0.90:
        return Signal(
            rule_id="R002_WASH_PATTERN",
            severity=SEVERITY_MAP["R002_WASH_PATTERN"],
            description="Total withdrawals ≥ 90% of deposits — wash-through pattern detected",
            evidence={
                "total_deposited": round(total_deposited, 2),
                "total_withdrawn": round(total_withdrawn, 2),
                "wash_ratio": round(wash_ratio, 4),
            },
        )
    return None


def rule_new_account_large_tx(data: dict, account: dict) -> Signal | None:
    """
    R003: Account < 7 days old with transaction > $1,000.
    High risk indicator per FATF Rec 10 (enhanced due diligence).
    """
    created_at = account.get("created_at", 0)
    account_age_days = (datetime.utcnow().timestamp() - created_at) / 86400

    txns = _transactions(data)
    large_txns = [t for t in txns if abs(t["amount"]) >= 1000]

    if account_age_days <= 7 and large_txns:
        return Signal(
            rule_id="R003_NEW_ACCOUNT_LARGE_TX",
            severity=SEVERITY_MAP["R003_NEW_ACCOUNT_LARGE_TX"],
            description="Account < 7 days old with transaction ≥ $1,000",
            evidence={
                "account_age_days": round(account_age_days, 1),
                "large_transaction_count": len(large_txns),
                "largest_amount": max(abs(t["amount"]) for t in large_txns),
            },
        )
    return None


def rule_geo_device_mismatch(data: dict) -> Signal | None:
    """
    R004: Transaction from new country/device while another session active in prior country.
    Primary account-takeover signal.
    """
    geo_change = data.get("geo_change")
    if not geo_change:
        return None

    ips = data.get("ip_addresses", [])
    devices = data.get("device_fingerprints", [])

    # Tor/VPN exit node heuristic (simplified — real system checks MaxMind)
    suspicious_ranges = ["185.220.", "185.107.", "198.98.", "185.129."]
    suspicious_ip = any(
        any(ip.startswith(r) for r in suspicious_ranges)
        for ip in ips
    )

    return Signal(
        rule_id="R004_GEO_DEVICE_MISMATCH",
        severity=SEVERITY_MAP["R004_GEO_DEVICE_MISMATCH"],
        description="Geographic shift + new device detected — possible account takeover",
        evidence={
            "previous_country": geo_change.get("previous"),
            "current_country": geo_change.get("current"),
            "hours_since_last_known_login": geo_change.get("hours_since_last_ng_login"),
            "new_device_detected": len(devices) > 1,
            "suspicious_ip_detected": suspicious_ip,
            "ip_count": len(ips),
        },
    )


def rule_device_overlap(data: dict) -> Signal | None:
    """
    R005: Multiple distinct accounts share the same device fingerprint or IP.
    Primary signal for coordinated fraud rings / mule accounts.
    """
    shared = data.get("shared_signals")
    accounts = data.get("accounts", [])

    if shared and len(accounts) >= 2:
        reg_gaps = shared.get("registration_gap_hours", [])
        max_gap = max(reg_gaps) if reg_gaps else 0
        return Signal(
            rule_id="R005_DEVICE_OVERLAP",
            severity=SEVERITY_MAP["R005_DEVICE_OVERLAP"],
            description=f"{len(accounts)} accounts share device/IP — coordinated fraud ring pattern",
            evidence={
                "shared_device_fingerprint": shared.get("device_fingerprint"),
                "shared_ip": shared.get("ip_address"),
                "account_count": len(accounts),
                "registration_span_hours": round(max_gap, 1),
                "account_ids": [a.get("loginid") for a in accounts],
            },
        )
    return None


def rule_high_win_rate(data: dict) -> Signal | None:
    """
    R006: Win rate > 80% on binary options — statistically anomalous.
    Possible insider knowledge, API manipulation, or front-running.
    """
    win_rate = data.get("win_rate")
    if win_rate is not None and win_rate > 0.80:
        return Signal(
            rule_id="R006_HIGH_WIN_RATE",
            severity=SEVERITY_MAP["R006_HIGH_WIN_RATE"],
            description=f"Win rate {win_rate:.0%} exceeds statistical maximum — possible manipulation",
            evidence={
                "win_rate": win_rate,
                "expected_max": 0.55,
                "deviation": round(win_rate - 0.55, 4),
            },
        )
    return None


def rule_velocity_spike(data: dict) -> Signal | None:
    """
    R007: More than 100 transactions in a 24-hour window.
    Could indicate bot trading or automated wash pattern.
    """
    txns = _transactions(data)
    now = datetime.utcnow()
    window_start = now - timedelta(hours=24)

    recent = [
        t for t in txns
        if _tx_time(t) >= window_start
    ]
    if len(recent) >= 100:
        return Signal(
            rule_id="R007_VELOCITY_SPIKE",
            severity=SEVERITY_MAP["R007_VELOCITY_SPIKE"],
            description=f"{len(recent)} transactions in 24h — velocity spike detected",
            evidence={
                "transactions_24h": len(recent),
                "threshold": 100,
            },
        )
    return None


def rule_crypto_withdrawal(data: dict) -> Signal | None:
    """
    R008: Withdrawal to crypto wallet where deposit was fiat.
    Risk factor for AML — changes of payment method type.
    """
    methods = data.get("payment_methods", [])
    has_fiat = any("bank" in m.lower() or "card" in m.lower() for m in methods)
    has_crypto = any("crypto" in m.lower() or "btc" in m.lower() or "eth" in m.lower() for m in methods)
    if has_fiat and has_crypto:
        return Signal(
            rule_id="R008_CRYPTO_WITHDRAWAL",
            severity=SEVERITY_MAP["R008_CRYPTO_WITHDRAWAL"],
            description="Mixed fiat-to-crypto payment method change detected",
            evidence={"payment_methods": methods},
        )
    return None


def rule_round_amount(data: dict) -> Signal | None:
    """
    R009: Multiple large round-number deposits ($1000, $5000, $10000).
    Structuring indicator (FATF — smurfing pattern below reporting thresholds).
    """
    txns = _transactions(data)
    deposits = [t for t in txns if t["action_type"] == "deposit"]
    round_large = [
        t for t in deposits
        if abs(t["amount"]) >= 500
        and abs(t["amount"]) % 500 == 0
    ]
    if len(round_large) >= 3:
        return Signal(
            rule_id="R009_ROUND_AMOUNT",
            severity=SEVERITY_MAP["R009_ROUND_AMOUNT"],
            description=f"{len(round_large)} round-number deposits ≥ $500 detected (structuring pattern)",
            evidence={
                "round_deposit_count": len(round_large),
                "amounts": [abs(t["amount"]) for t in round_large],
            },
        )
    return None


# ── Main entry ────────────────────────────────────────────────────────────────

def run_signal_agent(scenario_data: dict) -> SignalAgentResult:
    """
    Run all deterministic rules against a scenario.
    Returns a SignalAgentResult with scored risk tier.
    """
    account_id = (
        scenario_data.get("account", {}).get("loginid")
        or scenario_data.get("scenario_id", "UNKNOWN")
    )
    account = scenario_data.get("account", {})

    # Run each rule
    rule_results: list[Signal | None] = [
        rule_rapid_withdrawal(scenario_data),
        rule_wash_pattern(scenario_data),
        rule_new_account_large_tx(scenario_data, account),
        rule_geo_device_mismatch(scenario_data),
        rule_device_overlap(scenario_data),
        rule_high_win_rate(scenario_data),
        rule_velocity_spike(scenario_data),
        rule_crypto_withdrawal(scenario_data),
        rule_round_amount(scenario_data),
    ]

    triggered = [r for r in rule_results if r is not None]

    # Compute composite risk score (capped at 1.0)
    risk_score = min(
        sum(RULE_WEIGHTS.get(s.rule_id, 0.10) for s in triggered),
        1.0,
    )

    # Map to tier
    if risk_score >= 0.70 or any(s.severity == "CRITICAL" for s in triggered):
        risk_tier = "CRITICAL"
    elif risk_score >= 0.40 or any(s.severity == "HIGH" for s in triggered):
        risk_tier = "HIGH"
    elif risk_score >= 0.20 or any(s.severity == "MEDIUM" for s in triggered):
        risk_tier = "MEDIUM"
    else:
        risk_tier = "LOW"

    summary = (
        f"{len(triggered)} rule(s) triggered. "
        f"Composite risk score: {risk_score:.2f}. "
        f"Risk tier: {risk_tier}. "
        f"Top signal: {triggered[0].description if triggered else 'None'}."
    )

    return SignalAgentResult(
        account_id=account_id,
        signals=triggered,
        risk_score=risk_score,
        risk_tier=risk_tier,
        summary=summary,
    )


if __name__ == "__main__":
    import sys
    import json
    from data.synthetic_scenarios import get_scenario

    for sid in ["CLEAN-001", "WASH-001", "ATO-001", "MULE-001", "VEL-001"]:
        result = run_signal_agent(get_scenario(sid))
        print(f"\n[{sid}]")
        print(json.dumps(result.to_dict(), indent=2))
