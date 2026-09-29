"""
Telegram alerting for high-risk investigations.

Fires a notification after an investigation completes with an ESCALATE or
BLOCK verdict. Never raises — a Telegram failure must not break the
investigation response, since this is a side-channel notification, not
part of the investigation pipeline itself.
"""
from __future__ import annotations
import os
from typing import Any

import requests

_TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


def _format_message(result: dict[str, Any]) -> str:
    reasoning = result.get("reasoning", {})
    signal_analysis = result.get("signal_analysis", {})
    triggered = signal_analysis.get("triggered_rules", [])
    sig_score = signal_analysis.get("risk_score", 0)
    anomaly_score = result.get("pattern_analysis", {}).get("anomaly_score", 0)
    risk_score = round(sig_score * 0.6 * 100 + anomaly_score * 0.4 * 100)

    return (
        f"\U0001F6A8 FRAUD ALERT — {result.get('account_id')}\n"
        f"Classification: {result.get('risk_classification')}\n"
        f"Risk Score: {risk_score}/100\n"
        f"Signals: {', '.join(triggered) if triggered else 'none'}\n"
        f"Action: {result.get('ai_recommendation', 'Manual review required.')}\n"
        f"Investigated: {result.get('timestamp')}"
    )


def notify_if_high_risk(result: dict[str, Any]) -> None:
    """Send a Telegram alert for ESCALATE/BLOCK verdicts. Never raises."""
    verdict = result.get("verdict")
    if verdict not in ("ESCALATE", "BLOCK"):
        return

    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return

    try:
        requests.post(
            _TELEGRAM_API.format(token=token),
            json={"chat_id": chat_id, "text": _format_message(result)},
            timeout=5,
        )
    except Exception:
        pass
