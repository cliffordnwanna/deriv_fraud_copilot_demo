"""
Deriv WebSocket API client.
Public endpoints (no auth): active_symbols, ticks
Auth endpoints: statement, get_account_status, portfolio, profit_table

For the demo, we fall back to synthetic data when no token is provided,
preserving the exact same response shapes as the real API.
"""
from __future__ import annotations
import asyncio
import json
import os
from typing import Any

# Real Deriv WS endpoint
DERIV_WS_URL = "wss://ws.binaryws.com/websockets/v3?app_id=1089"

# ── Live API calls (requires DERIV_API_TOKEN env var) ─────────────────────────

async def _ws_call(payload: dict) -> dict:
    """Single WebSocket request-response to Deriv API."""
    try:
        import websockets
        async with websockets.connect(DERIV_WS_URL) as ws:
            await ws.send(json.dumps(payload))
            response = json.loads(await ws.recv())
            return response
    except Exception as e:
        return {"error": {"code": "ConnectionError", "message": str(e)}}


async def get_active_symbols() -> dict:
    """Public — no auth required. Returns list of available trading symbols."""
    return await _ws_call({
        "active_symbols": "brief",
        "product_type": "basic"
    })


async def get_statement(
    api_token: str | None = None,
    limit: int = 50,
    action_type: str | None = None,
) -> dict:
    """
    Fetch account statement. Auth required for real data.
    Falls back to synthetic data shape when no token.
    """
    token = api_token or os.environ.get("DERIV_API_TOKEN")
    if not token:
        # Return synthetic shape for demo
        return _synthetic_statement_response(limit=limit)

    payload: dict[str, Any] = {
        "statement": 1,
        "limit": limit,
    }
    if action_type:
        payload["action_type"] = action_type

    # Authorize first
    auth_resp = await _ws_call({"authorize": token})
    if "error" in auth_resp:
        return auth_resp

    return await _ws_call(payload)


async def get_account_status(api_token: str | None = None) -> dict:
    """Fetch account KYC/AML/status flags."""
    token = api_token or os.environ.get("DERIV_API_TOKEN")
    if not token:
        return _synthetic_account_status()

    auth_resp = await _ws_call({"authorize": token})
    if "error" in auth_resp:
        return auth_resp

    return await _ws_call({"get_account_status": 1})


async def get_profit_table(api_token: str | None = None, limit: int = 50) -> dict:
    """Fetch trading P&L table."""
    token = api_token or os.environ.get("DERIV_API_TOKEN")
    if not token:
        return _synthetic_profit_table(limit=limit)

    auth_resp = await _ws_call({"authorize": token})
    if "error" in auth_resp:
        return auth_resp

    return await _ws_call({"profit_table": 1, "limit": limit, "sort": "DESC"})


# ── Synthetic fallbacks (identical shapes to real API) ───────────────────────

def _synthetic_statement_response(limit: int = 10) -> dict:
    import random
    from datetime import datetime, timedelta

    def ts(h):
        return int((datetime.utcnow() - timedelta(hours=h)).timestamp())

    txns = [
        {"transaction_id": 123456789, "action_type": "deposit",    "amount": 1000.00,  "balance_after": 1000.00, "transaction_time": ts(168)},
        {"transaction_id": 123456790, "action_type": "buy",        "amount": -50.00,   "balance_after": 950.00,  "transaction_time": ts(120)},
        {"transaction_id": 123456791, "action_type": "sell",       "amount": 95.00,    "balance_after": 1045.00, "transaction_time": ts(119)},
        {"transaction_id": 123456792, "action_type": "withdrawal", "amount": -500.00,  "balance_after": 545.00,  "transaction_time": ts(24)},
        {"transaction_id": 123456793, "action_type": "deposit",    "amount": 2000.00,  "balance_after": 2545.00, "transaction_time": ts(12)},
        {"transaction_id": 123456794, "action_type": "withdrawal", "amount": -2490.00, "balance_after": 55.00,   "transaction_time": ts(1)},
    ]
    return {
        "statement": {
            "count": len(txns),
            "transactions": txns[:limit],
        },
        "req_id": 1,
        "_synthetic": True,
    }


def _synthetic_account_status() -> dict:
    return {
        "get_account_status": {
            "status": ["age_verification", "unwelcome"],
            "risk_classification": "high",
            "cashier_validation": ["system_maintenance"],
            "currency_config": {"USD": {"is_deposit_suspended": 0, "is_withdrawal_suspended": 0}},
        },
        "req_id": 2,
        "_synthetic": True,
    }


def _synthetic_profit_table(limit: int = 10) -> dict:
    from datetime import datetime, timedelta
    ts = lambda h: int((datetime.utcnow() - timedelta(hours=h)).timestamp())
    contracts = [
        {"contract_id": 1001, "buy_price": 50.00, "sell_price": 95.00, "profit": 45.00, "purchase_time": ts(120), "sell_time": ts(119)},
        {"contract_id": 1002, "buy_price": 50.00, "sell_price": 95.00, "profit": 45.00, "purchase_time": ts(100), "sell_time": ts(99)},
        {"contract_id": 1003, "buy_price": 50.00, "sell_price": 95.00, "profit": 45.00, "purchase_time": ts(80),  "sell_time": ts(79)},
    ]
    return {
        "profit_table": {"count": len(contracts), "transactions": contracts[:limit]},
        "req_id": 3,
        "_synthetic": True,
    }


# ── Sync wrappers ─────────────────────────────────────────────────────────────

def fetch_statement(api_token: str | None = None, limit: int = 50) -> dict:
    return asyncio.run(get_statement(api_token=api_token, limit=limit))

def fetch_account_status(api_token: str | None = None) -> dict:
    return asyncio.run(get_account_status(api_token=api_token))

def fetch_profit_table(api_token: str | None = None, limit: int = 50) -> dict:
    return asyncio.run(get_profit_table(api_token=api_token, limit=limit))
