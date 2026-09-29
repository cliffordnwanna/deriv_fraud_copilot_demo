"""
Minimal live Deriv connector.
Authenticates once over a single WebSocket connection (authorize + balance),
proving real account integration without executing any trading/account actions.
"""
from __future__ import annotations
import asyncio
import json
import os

DERIV_WS = "wss://ws.derivws.com/websockets/v3?app_id={}"


async def fetch_live_account() -> dict | None:
    app_id = os.getenv("DERIV_APP_ID", "1089")
    token = os.getenv("DERIV_API_TOKEN")
    if not token:
        return None

    try:
        import websockets
        async with websockets.connect(DERIV_WS.format(app_id)) as ws:
            await ws.send(json.dumps({"authorize": token}))
            auth = json.loads(await ws.recv())
            if auth.get("error"):
                return {"error": auth["error"]["message"]}

            await ws.send(json.dumps({"balance": 1, "subscribe": 0}))
            bal = json.loads(await ws.recv())
            if bal.get("error"):
                return {"error": bal["error"]["message"]}

            return {
                "account_id": auth["authorize"]["loginid"],
                "currency": auth["authorize"]["currency"],
                "balance": bal["balance"]["balance"],
                "email": auth["authorize"]["email"],
            }
    except Exception as e:
        return {"error": str(e)}


def get_live_account() -> dict | None:
    return asyncio.run(fetch_live_account())
