"""
Pattern Agent — Software 2.0 (statistical / ML layer)
Applies statistical anomaly detection to transaction sequences.
No external ML model required — uses numpy/scipy for Z-score analysis
and temporal feature extraction. Designed to be swappable for a
trained model (CoLES/GraphSAGE embeddings) in production.

In production at Deriv this would feed into the FRL-System pipeline:
  Transaction sequence → Event Tokenizer → CoLES encoder → anomaly score
"""
from __future__ import annotations
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class PatternSignal:
    pattern_id: str
    description: str
    score: float           # 0.0–1.0 anomaly score
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class PatternAgentResult:
    account_id: str
    anomaly_score: float      # composite 0.0–1.0
    patterns: list[PatternSignal] = field(default_factory=list)
    temporal_features: dict = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "anomaly_score": round(self.anomaly_score, 4),
            "patterns": [
                {
                    "pattern_id": p.pattern_id,
                    "description": p.description,
                    "score": round(p.score, 4),
                    "evidence": p.evidence,
                }
                for p in self.patterns
            ],
            "temporal_features": self.temporal_features,
            "summary": self.summary,
        }


# ── Statistical helpers ───────────────────────────────────────────────────────

def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0

def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    return math.sqrt(sum((x - m) ** 2 for x in values) / (len(values) - 1))

def _zscore(value: float, mean: float, std: float) -> float:
    return abs((value - mean) / std) if std > 0 else 0.0

def _sigmoid(x: float) -> float:
    """Map z-score (0–∞) to probability (0–1)."""
    return 1 / (1 + math.exp(-0.5 * (x - 2)))


# ── Feature extraction ────────────────────────────────────────────────────────

def extract_temporal_features(transactions: list[dict]) -> dict:
    """
    Extract time-series features from transaction sequence.
    These would feed into CoLES encoder in production.
    """
    if not transactions:
        return {}

    amounts = [abs(t.get("amount", 0)) for t in transactions]
    times = [t.get("transaction_time", 0) for t in transactions]
    times_sorted = sorted(times)

    # Inter-arrival times (seconds between transactions)
    inter_arrivals = [
        times_sorted[i] - times_sorted[i - 1]
        for i in range(1, len(times_sorted))
    ]

    deposits = [t for t in transactions if t["action_type"] == "deposit"]
    withdrawals = [t for t in transactions if t["action_type"] == "withdrawal"]
    trades = [t for t in transactions if t["action_type"] in ("buy", "sell")]

    deposit_amounts = [abs(t["amount"]) for t in deposits]
    withdrawal_amounts = [abs(t["amount"]) for t in withdrawals]
    trade_amounts = [abs(t["amount"]) for t in trades]

    total_deposited = sum(deposit_amounts)
    total_withdrawn = sum(withdrawal_amounts)

    # Leave-one-out baseline for the max: testing whether the max is an
    # outlier using a mean/std computed *with* the max included is a known
    # masking-effect bias (the outlier inflates its own baseline, hiding
    # itself). Excluding it gives an honest baseline to test against.
    if len(amounts) >= 2:
        max_val = max(amounts)
        rest = amounts[:]
        rest.remove(max_val)
        baseline_mean = _mean(rest)
        baseline_std = _std(rest)
    else:
        baseline_mean = _mean(amounts)
        baseline_std = _std(amounts)

    return {
        "transaction_count": len(transactions),
        "deposit_count": len(deposits),
        "withdrawal_count": len(withdrawals),
        "trade_count": len(trades),
        "total_deposited": round(total_deposited, 2),
        "total_withdrawn": round(total_withdrawn, 2),
        "wash_ratio": round(total_withdrawn / total_deposited, 4) if total_deposited > 0 else 0.0,
        "mean_amount": round(_mean(amounts), 2),
        "std_amount": round(_std(amounts), 2),
        "max_excl_mean": round(baseline_mean, 2),
        "max_excl_std": round(baseline_std, 2),
        "max_amount": round(max(amounts), 2) if amounts else 0,
        "mean_inter_arrival_hours": round(_mean(inter_arrivals) / 3600, 2) if inter_arrivals else 0,
        "min_inter_arrival_hours": round(min(inter_arrivals) / 3600, 4) if inter_arrivals else 0,
        "trade_to_deposit_ratio": round(sum(trade_amounts) / total_deposited, 4) if total_deposited > 0 else 0.0,
    }


# ── Anomaly detectors ─────────────────────────────────────────────────────────

def detect_amount_anomaly(features: dict, population_baseline: dict | None = None) -> PatternSignal | None:
    """
    Z-score on transaction amounts.

    When a population baseline is available (real accounts, via
    get_population_statistics), the max is scored against the population's
    deposit distribution rather than the account's own — testing a value
    against statistics computed from that same value is a masking-effect
    bias that produces false anomalies on ordinary accounts with only a
    handful of transactions. Synthetic scenarios have no population
    baseline and keep the original self-relative behaviour they were
    calibrated against.
    """
    max_amt = features.get("max_amount", 0)
    n = features.get("transaction_count", 0)

    if population_baseline:
        mean = population_baseline.get("mean", 0)
        std = population_baseline.get("std", 0)
        baseline_label = "population"
    else:
        mean = features.get("mean_amount", 0)
        std = features.get("std_amount", 0)
        baseline_label = "account"

    if mean == 0:
        return None

    z = _zscore(max_amt, mean, std) if std > 0 else 0

    # A self-relative baseline (mean/std computed from the same small sample
    # being tested) is statistically noisy: with only a handful of
    # transactions, one normal larger-than-average transaction produces a
    # high z-score from sampling variance alone, not genuine anomaly. Require
    # a higher bar in that case; a population baseline doesn't have this
    # problem since it isn't derived from the value being tested.
    if baseline_label == "account" and n < 30:
        z = max(0.0, z - 1.5)

    score = _sigmoid(z)

    if score > 0.5:
        return PatternSignal(
            pattern_id="P001_AMOUNT_ANOMALY",
            description=f"Maximum transaction amount is statistically anomalous relative to {baseline_label} baseline",
            score=score,
            evidence={
                "z_score": round(z, 3),
                "max_amount": max_amt,
                "baseline_mean": round(mean, 2),
                "baseline_std": round(std, 2),
                "baseline": baseline_label,
            },
        )
    return None


def detect_velocity_anomaly(features: dict) -> PatternSignal | None:
    """
    Unusually short inter-arrival time → automated/bot behaviour.
    """
    min_iat_hours = features.get("min_inter_arrival_hours", 999)
    if min_iat_hours < 0.01:  # < 36 seconds between transactions
        score = min(1.0, 0.01 / max(min_iat_hours, 0.0001))
        score = min(score, 0.95)
        return PatternSignal(
            pattern_id="P002_VELOCITY_ANOMALY",
            description="Transactions occurring seconds apart — likely automated/bot activity",
            score=round(score, 4),
            evidence={
                "min_inter_arrival_hours": min_iat_hours,
                "min_inter_arrival_seconds": round(min_iat_hours * 3600, 1),
            },
        )
    return None


def detect_wash_anomaly(features: dict) -> PatternSignal | None:
    """
    High withdrawal ratio relative to deposits with low trade activity.
    """
    wash_ratio = features.get("wash_ratio", 0)
    trade_ratio = features.get("trade_to_deposit_ratio", 0)

    if wash_ratio >= 0.85 and trade_ratio <= 0.05:
        score = min(0.95, wash_ratio * 0.8 + (1 - trade_ratio) * 0.2)
        return PatternSignal(
            pattern_id="P003_WASH_ANOMALY",
            description="High withdrawal-to-deposit ratio with minimal trading — statistically consistent with wash pattern",
            score=round(score, 4),
            evidence={
                "wash_ratio": wash_ratio,
                "trade_to_deposit_ratio": trade_ratio,
                "total_deposited": features.get("total_deposited"),
                "total_withdrawn": features.get("total_withdrawn"),
            },
        )
    return None


def detect_concentration_anomaly(features: dict) -> PatternSignal | None:
    """
    Very few large transactions vs. many small ones.
    Gini coefficient proxy.
    """
    n = features.get("transaction_count", 0)
    mean = features.get("mean_amount", 0)
    std = features.get("std_amount", 0)

    if n < 3 or mean == 0:
        return None

    cv = std / mean  # coefficient of variation
    if cv > 3.0:  # high concentration = a few very large outliers
        score = min(0.90, cv / 6.0)
        return PatternSignal(
            pattern_id="P004_CONCENTRATION_ANOMALY",
            description="Transaction amount distribution highly concentrated — few large outliers dominate",
            score=round(score, 4),
            evidence={
                "coefficient_of_variation": round(cv, 3),
                "mean_amount": round(mean, 2),
                "std_amount": round(std, 2),
            },
        )
    return None


# ── Main entry ────────────────────────────────────────────────────────────────

def run_pattern_agent(scenario_data: dict) -> PatternAgentResult:
    account_id = (
        scenario_data.get("account", {}).get("loginid")
        or scenario_data.get("scenario_id", "UNKNOWN")
    )

    # Collect transactions (single account or multi-account scenario)
    if "statement" in scenario_data:
        txns = scenario_data["statement"].get("transactions", [])
    elif "statements" in scenario_data:
        # Mule ring scenario: aggregate all accounts' transactions
        txns = []
        for stmt in scenario_data["statements"].values():
            txns.extend(stmt.get("transactions", []))
    else:
        txns = []

    features = extract_temporal_features(txns)

    population_baseline = None
    pop_stats = scenario_data.get("_population_statistics")
    if pop_stats and pop_stats.get("total_deposited"):
        # Deposit-amount distribution is the closest population analogue to a
        # single account's per-transaction amount baseline in this dataset.
        population_baseline = {
            "mean": pop_stats["total_deposited"].get("mean", 0),
            "std": pop_stats["total_deposited"].get("std", 0),
        }

    detectors = [
        detect_amount_anomaly(features, population_baseline),
        detect_velocity_anomaly(features),
        detect_wash_anomaly(features),
        detect_concentration_anomaly(features),
    ]
    triggered = [d for d in detectors if d is not None]

    # Composite score: max of individual scores (they're not independent)
    anomaly_score = max((p.score for p in triggered), default=0.0)

    # Boost if multiple patterns co-occur
    if len(triggered) >= 2:
        anomaly_score = min(1.0, anomaly_score * 1.15)

    summary = (
        f"{len(triggered)} statistical pattern(s) detected. "
        f"Anomaly score: {anomaly_score:.2f}. "
        f"Key: {triggered[0].description if triggered else 'No anomalies detected'}."
    )

    return PatternAgentResult(
        account_id=account_id,
        anomaly_score=round(anomaly_score, 4),
        patterns=triggered,
        temporal_features=features,
        summary=summary,
    )


if __name__ == "__main__":
    import sys
    import json
    from data.synthetic_scenarios import get_scenario

    for sid in ["CLEAN-001", "WASH-001", "ATO-001"]:
        result = run_pattern_agent(get_scenario(sid))
        print(f"\n[{sid}]")
        print(json.dumps(result.to_dict(), indent=2))
