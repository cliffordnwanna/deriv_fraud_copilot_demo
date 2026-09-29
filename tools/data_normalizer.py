"""
Normalizes tools.data_connector account data into the scenario_data shape
consumed by agents.signal_agent.run_signal_agent and
agents.pattern_agent.run_pattern_agent (see data/synthetic_scenarios.py).

Keeps the existing agents unchanged; only the input shape is adapted so real
SQLite-backed accounts and synthetic scenarios flow through the same pipeline.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

from tools.data_connector import (
    get_account,
    get_transactions,
    get_trades,
    get_device_fingerprints,
    get_complaints,
    get_login_events,
    get_payment_methods,
    get_linked_accounts,
    get_population_statistics,
)


def _to_epoch(ts_str: str | None) -> int:
    if not ts_str:
        return 0
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return int(dt.timestamp())
    except Exception:
        return 0


def _statement_transaction(tx: dict) -> dict:
    """Map a data_connector transactions row to the Deriv statement shape."""
    action_type = {
        "deposit": "deposit",
        "withdrawal": "withdrawal",
    }.get(tx.get("transaction_type"), tx.get("transaction_type"))
    amount = float(tx.get("amount", 0))
    if action_type == "withdrawal":
        amount = -abs(amount)
    return {
        "transaction_id": tx.get("transaction_id"),
        "action_type": action_type,
        "amount": amount,
        "balance_after": None,
        "transaction_time": _to_epoch(tx.get("timestamp")),
        "purchase_time": None,
        "app_id": 1,
        "longcode": tx.get("notes", ""),
        "payout": None,
        "reference_id": None,
        "short_code": None,
        "country": None,
    }


def _trade_as_transaction(trade: dict) -> dict:
    """Represent a trade row as buy/sell pair so signal/pattern agents that
    scan action_type in ('buy','sell') pick up trading activity."""
    stake = float(trade.get("stake_usd", 0) or 0)
    payout = float(trade.get("payout_usd", 0) or 0)
    ts = _to_epoch(trade.get("timestamp"))
    return {
        "transaction_id": trade.get("trade_id"),
        "action_type": "sell" if trade.get("result") == "win" else "buy",
        "amount": payout if trade.get("result") == "win" else -stake,
        "balance_after": None,
        "transaction_time": ts,
        "purchase_time": ts,
        "app_id": 1,
        "longcode": f"{trade.get('contract_type','')} on {trade.get('asset','')}",
        "payout": payout if trade.get("result") == "win" else None,
        "reference_id": None,
        "short_code": None,
        "country": None,
    }


def build_scenario_data(account_id: str) -> dict[str, Any]:
    """
    Fetch a real account from the data connector and normalize it into the
    same dict shape as data/synthetic_scenarios.get_scenario(), so it can be
    passed unmodified into agents.orchestrator.investigate().
    """
    account = get_account(account_id)
    txn_data = get_transactions(account_id)
    trade_data = get_trades(account_id)
    device_data = get_device_fingerprints(account_id)
    complaint_data = get_complaints(account_id)
    login_data = get_login_events(account_id)
    payment_data = get_payment_methods(account_id)
    linked_data = get_linked_accounts(account_id)

    transactions = [_statement_transaction(t) for t in txn_data.get("transactions", [])]
    transactions += [_trade_as_transaction(t) for t in trade_data.get("trades", [])]
    transactions.sort(key=lambda t: t["transaction_time"])

    # Source timestamps have minute-level precision, so unrelated records can
    # collide on the same minute. A 1-second nudge would fall inside the
    # pattern agent's bot-velocity window (<36s) and fabricate a false signal,
    # so instead drop exact-timestamp duplicates that follow immediately —
    # they carry no additional inter-arrival information anyway.
    deduped = []
    for t in transactions:
        if deduped and t["transaction_time"] == deduped[-1]["transaction_time"]:
            continue
        deduped.append(t)
    transactions = deduped

    device_ids = list({d.get("device_id") for d in device_data.get("fingerprints", []) if d.get("device_id")})
    ip_addresses = list({
        d.get("ip_address") for d in device_data.get("fingerprints", []) if d.get("ip_address")
    } | {
        t.get("ip_address") for t in txn_data.get("transactions", []) if t.get("ip_address")
    })

    payment_methods = [
        f"{p.get('method_type', 'unknown')}_{p.get('bin_country', '')}".strip("_")
        for p in payment_data.get("payment_methods", [])
    ]

    geo_change = None
    if device_data.get("summary", {}).get("new_device_last_7d") and login_data.get("summary", {}).get("unique_countries", 0) > 1:
        countries = device_data["summary"].get("countries_seen", [])
        geo_change = {
            "previous": countries[0] if countries else None,
            "current": countries[-1] if len(countries) > 1 else None,
            "hours_since_last_ng_login": None,
        }

    linked = linked_data.get("linked_accounts", [])
    shared_signals = None
    accounts_field = []
    if linked:
        device_links = [l for l in linked if l.get("link_type") == "device"]
        shared_signals = {
            "device_fingerprint": device_ids[0] if device_ids else None,
            "ip_address": ip_addresses[0] if ip_addresses else None,
            "registration_gap_hours": [],
        }
        accounts_field = [{"loginid": account_id}] + [{"loginid": l["account_id"]} for l in linked]

    trade_summary = trade_data.get("summary", {})

    return {
        "scenario_id": account_id,
        "description": f"Live account {account_id} ({account.get('full_name', 'unknown')})",
        "expected_outcome": None,
        "account": {
            "loginid": account_id,
            "account_type": "real",
            "currency": account.get("currency", "USD"),
            "balance": account.get("net_balance", 0),
            "country": account.get("country_name"),
            "country_code": account.get("country_code"),
            "created_at": _to_epoch(account.get("account_created_at")),
            "email": account.get("email"),
            "phone": account.get("phone"),
            "first_name": (account.get("full_name") or "").split(" ")[0],
            "last_name": (account.get("full_name") or "").split(" ")[-1],
            "date_of_birth": account.get("date_of_birth"),
            "status": [],
            "risk_classification": "unknown",
            "account_opening_reason": None,
        },
        "statement": {"transactions": transactions},
        "device_fingerprints": device_ids,
        "ip_addresses": ip_addresses,
        "payment_methods": payment_methods,
        "win_rate": trade_summary.get("win_rate"),
        "geo_change": geo_change,
        "shared_signals": shared_signals,
        "accounts": accounts_field,
        "data_source": account.get("data_source", "unavailable"),
        "_population_statistics": get_population_statistics(),
        "_connector_context": {
            "complaints": complaint_data.get("summary", {}),
            "login_events": login_data.get("summary", {}),
            "payment_methods": payment_data.get("summary", {}),
            "device_fingerprints": device_data.get("summary", {}),
            "linked_accounts": {"count": linked_data.get("count", 0)},
        },
    }
