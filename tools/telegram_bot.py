"""
Interactive Telegram bot: send an account ID, get back a full investigation
report. Runs as a background asyncio task inside the FastAPI process using
long polling — no public webhook needed, unlike the Slack integration.

The investigation pipeline (run_investigation in api.py) is synchronous and
can take several seconds (LLM call), so it's run via asyncio.to_thread to
avoid blocking the bot's event loop, which would otherwise freeze replies
to other chats while one investigation is in flight.
"""
from __future__ import annotations
import asyncio
import logging
import os
import re

logger = logging.getLogger("telegram_bot")

_ACCOUNT_ID_PATTERN = re.compile(r"\bCR-\d+\b", re.IGNORECASE)

_bot_task: asyncio.Task | None = None


def _classification_label(verdict: str) -> str:
    return {
        "CLEAR": "CLEAR",
        "REVIEW": "REVIEW REQUIRED",
        "ESCALATE": "HIGH RISK",
        "BLOCK": "CRITICAL RISK",
    }.get(verdict, verdict)


def _format_report(result: dict) -> str:
    reasoning = result.get("reasoning", {})
    signal_analysis = result.get("signal_analysis", {})
    triggered = signal_analysis.get("triggered_rules", [])
    sig_score = signal_analysis.get("risk_score", 0)
    anomaly_score = result.get("pattern_analysis", {}).get("anomaly_score", 0)
    risk_score = round(sig_score * 0.6 * 100 + anomaly_score * 0.4 * 100)
    confidence = reasoning.get("confidence")
    conf_pct = round(confidence * 100) if confidence is not None else "—"
    policies = result.get("policy_context", {}).get("policies_retrieved", [])

    account_id = result.get("account_id", "UNKNOWN")
    verdict = result.get("verdict", "REVIEW")

    lines = [
        "\U0001F3E6 FRAUD INVESTIGATION REPORT",
        f"Account: {account_id}",
        "━" * 20,
        f"\U0001F3AF Classification: {_classification_label(verdict)}",
        f"\U0001F4CA Risk Score: {risk_score}/100",
        f"\U0001F512 Confidence: {conf_pct}%" if confidence is not None else "",
        "",
    ]

    if triggered:
        lines.append("\U0001F6A8 Triggered Signals:")
        lines.extend(f"• {rule}" for rule in triggered)
        lines.append("")

    if policies:
        lines.append("\U0001F4CB Policy Matches:")
        lines.extend(f"• {pid}" for pid in policies)
        lines.append("")

    lines.append("\U0001F4A1 AI Recommendation:")
    lines.append(result.get("ai_recommendation", "Manual review required."))
    lines.append("")
    lines.append("AI advises · Human decides")

    return "\n".join(line for line in lines if line is not None)


async def _handle_message(update, context) -> None:
    text = update.message.text or ""
    match = _ACCOUNT_ID_PATTERN.search(text)

    if not match:
        await update.message.reply_text("Send an account ID to investigate, e.g. CR-00062")
        return

    account_id = match.group(0).upper()
    await update.message.reply_text(f"\U0001F50D Investigating {account_id}...")

    from api import run_investigation

    try:
        result = await asyncio.to_thread(run_investigation, account_id)
    except ValueError:
        await update.message.reply_text(f"❌ Account {account_id} not found in the system.")
        return
    except Exception:
        logger.exception("Investigation failed for %s", account_id)
        await update.message.reply_text(
            f"⚠️ Investigation of {account_id} failed unexpectedly. Check server logs."
        )
        return

    await update.message.reply_text(_format_report(result))


async def start_bot() -> None:
    """
    Start the Telegram bot as a long-running background task.
    No-op if TELEGRAM_BOT_TOKEN is not configured. Never raises out of this
    function — a bad token or network issue must not affect the FastAPI
    process, since the bot is a side feature, not core to the pipeline.
    """
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        logger.info("TELEGRAM_BOT_TOKEN not set — Telegram bot disabled.")
        return

    from telegram import Update
    from telegram.ext import Application, MessageHandler, filters

    app = Application.builder().token(token).build()
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, _handle_message))

    try:
        await app.initialize()
        await app.start()
        await app.updater.start_polling(allowed_updates=Update.ALL_TYPES)
        logger.info("Telegram bot started (polling).")

        # Keep the task alive for as long as the FastAPI app runs.
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("Telegram bot failed to start or crashed — continuing without it.")
    finally:
        try:
            await app.updater.stop()
            await app.stop()
            await app.shutdown()
        except Exception:
            pass


def launch_background(loop: asyncio.AbstractEventLoop) -> asyncio.Task | None:
    """Schedule start_bot() on the given event loop. Returns the task, or
    None if the bot is not configured."""
    global _bot_task
    if not os.environ.get("TELEGRAM_BOT_TOKEN"):
        return None
    _bot_task = loop.create_task(start_bot())
    return _bot_task
