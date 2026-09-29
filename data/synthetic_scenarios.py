"""
Synthetic fraud scenarios matching Deriv's actual API response shapes.
Deriv WebSocket API: https://api.deriv.com/api-explorer
Account Statement shape derived from: statement request/response in Deriv API docs.
"""
from __future__ import annotations
import random
import uuid
from datetime import datetime, timedelta
from typing import Any

# ── Helpers ─────────────────────────────────────────────────────────────────

def _ts(offset_hours: float = 0) -> int:
    return int((datetime.utcnow() - timedelta(hours=offset_hours)).timestamp())

def _txid() -> str:
    return str(random.randint(100_000_000, 999_999_999))

# ── Deriv Statement Transaction (matches API shape) ──────────────────────────
# Ref: https://api.deriv.com/api-explorer#statement
def make_transaction(
    action_type: str,
    amount: float,
    balance_after: float,
    offset_hours: float = 0,
    country_code: str = "NG",
    app_id: int = 1,
) -> dict[str, Any]:
    return {
        "transaction_id": int(_txid()),
        "action_type": action_type,            # deposit | withdrawal | buy | sell
        "amount": amount,
        "balance_after": balance_after,
        "transaction_time": _ts(offset_hours),
        "purchase_time": _ts(offset_hours) if action_type in ("buy",) else None,
        "app_id": app_id,
        "longcode": f"Win payout if market moves | Amount: {abs(amount):.2f} USD",
        "payout": abs(amount) * 1.85 if action_type == "buy" else None,
        "reference_id": None,
        "short_code": None,
        "country": country_code,
    }


# ── Deriv Get Account Info (matches API shape) ────────────────────────────────
# Ref: https://api.deriv.com/api-explorer#get_account_status
def make_account_profile(
    loginid: str,
    country: str = "Nigeria",
    country_code: str = "NG",
    age_days: int = 30,
    is_virtual: bool = False,
) -> dict[str, Any]:
    created_at = _ts(age_days * 24)
    return {
        "loginid": loginid,
        "account_type": "real" if not is_virtual else "virtual",
        "currency": "USD",
        "balance": round(random.uniform(100, 50_000), 2),
        "country": country,
        "country_code": country_code,
        "created_at": created_at,
        "email": f"user_{loginid.lower()}@example.com",
        "phone": f"+234{random.randint(7000000000, 9999999999)}",
        "first_name": "Test",
        "last_name": "User",
        "date_of_birth": "1985-03-15",
        "status": ["age_verification", "financial_information_not_complete"],
        "risk_classification": "low",
        "account_opening_reason": "Speculative",
    }


# ── Scenario 1: CLEAN baseline ────────────────────────────────────────────────
SCENARIO_CLEAN = {
    "scenario_id": "CLEAN-001",
    "description": "Normal retail trader: regular deposits, active trading, no anomalies",
    "expected_outcome": "CLEAR",
    "account": make_account_profile("CR100001", age_days=180),
    "statement": {
        "transactions": [
            make_transaction("deposit",    500.00,  500.00, offset_hours=720),
            make_transaction("buy",        -50.00,  450.00, offset_hours=715),
            make_transaction("sell",        90.00,  540.00, offset_hours=710),
            make_transaction("buy",        -60.00,  480.00, offset_hours=705),
            make_transaction("sell",        55.00,  535.00, offset_hours=700),
            make_transaction("withdrawal",-200.00,  335.00, offset_hours=336),
            make_transaction("deposit",    300.00,  635.00, offset_hours=168),
            make_transaction("buy",        -80.00,  555.00, offset_hours=12),
            make_transaction("sell",       150.00,  705.00, offset_hours=6),
        ]
    },
    "device_fingerprints": ["fp_a1b2c3"],
    "ip_addresses": ["41.58.100.25"],
    "payment_methods": ["bank_transfer_NG_001"],
}


# ── Scenario 2: RAPID DEPOSIT → WITHDRAWAL (wash) ────────────────────────────
SCENARIO_WASH = {
    "scenario_id": "WASH-001",
    "description": "Account deposits large sum, minimal/zero trading, immediate withdrawal — classic wash pattern",
    "expected_outcome": "ESCALATE",
    "account": make_account_profile("CR200001", country="Nigeria", age_days=3),
    "statement": {
        "transactions": [
            make_transaction("deposit",   10_000.00, 10_000.00, offset_hours=72),
            make_transaction("buy",          -10.00,  9_990.00, offset_hours=71.9),
            make_transaction("sell",          9.50,   9_999.50, offset_hours=71.8),
            make_transaction("withdrawal", -9_950.00,    49.50, offset_hours=48),
        ]
    },
    "device_fingerprints": ["fp_x9y8z7"],
    "ip_addresses": ["197.210.55.100"],
    "payment_methods": ["crypto_BTC_wallet_1A2b3C"],
}


# ── Scenario 3: ACCOUNT TAKEOVER signals ─────────────────────────────────────
SCENARIO_ATO = {
    "scenario_id": "ATO-001",
    "description": "Sudden login from new country + device, immediate large withdrawal — account takeover pattern",
    "expected_outcome": "BLOCK",
    "account": make_account_profile("CR300001", country="Nigeria", age_days=365),
    "statement": {
        "transactions": [
            # History: 12 months of normal Nigerian activity
            make_transaction("deposit",    2_000.00,  2_000.00, offset_hours=8760),
            make_transaction("buy",          -200.00,  1_800.00, offset_hours=8700),
            make_transaction("sell",          380.00,  2_180.00, offset_hours=8600),
            make_transaction("withdrawal",  -1_000.00, 1_180.00, offset_hours=4380),
            make_transaction("deposit",    1_500.00,  2_680.00, offset_hours=720),
            make_transaction("buy",          -300.00,  2_380.00, offset_hours=700),
            make_transaction("sell",          560.00,  2_940.00, offset_hours=680),
            # Anomaly: large withdrawal from entirely new location
            make_transaction("withdrawal", -2_800.00,   140.00, offset_hours=1,
                             country_code="RU"),
        ]
    },
    "device_fingerprints": ["fp_legacy_NG", "fp_legacy_NG2", "fp_NEW_unknown_RU"],
    "ip_addresses": ["41.58.100.25", "41.58.100.26", "185.220.101.5"],  # Last IP = Tor exit
    "payment_methods": ["bank_transfer_NG_001", "crypto_ETH_wallet_NEW"],
    "geo_change": {
        "previous": "NG",
        "current": "RU",
        "hours_since_last_ng_login": 2,
    },
}


# ── Scenario 4: NETWORK OVERLAP (mule ring) ──────────────────────────────────
SCENARIO_MULE = {
    "scenario_id": "MULE-001",
    "description": "Three accounts share device fingerprint and IP — likely coordinated mule ring",
    "expected_outcome": "ESCALATE",
    "accounts": [
        make_account_profile("CR400001", country="Ghana", age_days=45),
        make_account_profile("CR400002", country="Ghana", age_days=44),
        make_account_profile("CR400003", country="Ghana", age_days=43),
    ],
    "shared_signals": {
        "device_fingerprint": "fp_shared_device_RING",
        "ip_address": "154.160.20.15",
        "registration_gap_hours": [0, 26, 51],  # all registered within ~2 days
    },
    "statements": {
        "CR400001": {
            "transactions": [
                make_transaction("deposit", 3_000.00, 3_000.00, offset_hours=1000),
                make_transaction("withdrawal", -2_950.00, 50.00, offset_hours=999),
            ]
        },
        "CR400002": {
            "transactions": [
                make_transaction("deposit", 2_500.00, 2_500.00, offset_hours=975),
                make_transaction("withdrawal", -2_450.00, 50.00, offset_hours=974),
            ]
        },
        "CR400003": {
            "transactions": [
                make_transaction("deposit", 4_000.00, 4_000.00, offset_hours=950),
                make_transaction("withdrawal", -3_950.00, 50.00, offset_hours=949),
            ]
        },
    },
    "expected_outcome": "ESCALATE",
}


# ── Scenario 5: HIGH VELOCITY trading (potential market abuse) ────────────────
SCENARIO_VELOCITY = {
    "scenario_id": "VEL-001",
    "description": "500+ trades in 24 hours with suspiciously high win rate — possible front-running or manipulation",
    "expected_outcome": "REVIEW",
    "account": make_account_profile("CR500001", country="Cyprus", age_days=90),
    "statement": {
        "transactions": [
            # 48 hours of high-frequency trading
            *[
                make_transaction(
                    action_type="buy" if i % 2 == 0 else "sell",
                    amount=-50.0 if i % 2 == 0 else 95.0,
                    balance_after=10_000 + (i * 22.5),
                    offset_hours=48 - (i * 0.09),
                )
                for i in range(500)
            ]
        ]
    },
    "win_rate": 0.94,  # suspiciously high (normal max ~55%)
    "device_fingerprints": ["fp_automated_agent_v2"],
    "ip_addresses": ["185.183.100.50"],
    "expected_outcome": "REVIEW",
}


# ── All scenarios ─────────────────────────────────────────────────────────────
ALL_SCENARIOS = {
    "CLEAN-001": SCENARIO_CLEAN,
    "WASH-001":  SCENARIO_WASH,
    "ATO-001":   SCENARIO_ATO,
    "MULE-001":  SCENARIO_MULE,
    "VEL-001":   SCENARIO_VELOCITY,
}


def get_scenario(scenario_id: str) -> dict[str, Any]:
    if scenario_id not in ALL_SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario_id}. Available: {list(ALL_SCENARIOS)}")
    return ALL_SCENARIOS[scenario_id]


def list_scenarios() -> list[dict[str, str]]:
    return [
        {
            "id": sid,
            "description": s["description"],
            "expected_outcome": s.get("expected_outcome", "UNKNOWN"),
        }
        for sid, s in ALL_SCENARIOS.items()
    ]


if __name__ == "__main__":
    import json
    for s in list_scenarios():
        print(f"[{s['id']}] {s['description']} → {s['expected_outcome']}")
