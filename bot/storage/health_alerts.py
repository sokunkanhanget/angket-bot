"""
bot/storage/health_alerts.py
===============================
Admin alerting for repeated Gemini/VirusTotal/Supabase failures. Before
this, the bot degraded gracefully but SILENTLY on a backend outage -
nobody on the team found out unless a user complained. This closes
that gap with two changes: (1) real WARNING-level log lines at every
degraded-mode entry point, tagged consistently so they're easy to grep
for, and (2) an actual Telegram message to an admin once a service has
failed repeatedly, not just once (a single failure is normal - VT/
Gemini/Supabase all have real, expected transient blips already handled
by this codebase's existing fallback paths; a PATTERN of failures is
what actually needs a human).

Sends the alert via a raw HTTP call to Telegram's Bot API using just
the bot token - deliberately NOT through a python-telegram-bot Context
object, since several real failure sites (threat_intel.py's VT lookup,
vectors.py's Supabase calls) are low-level detector functions with no
Context available at all, and plumbing one through every call chain
just for this would be a much bigger, more invasive change than the
alerting feature itself needs.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

import httpx

from bot.config.config import ADMIN_CHAT_ID, DISPLAY_TIMEZONE_OFFSET_HOURS, TELEGRAM_BOT_TOKEN
from bot.response.verdict_style import DISCLAIMER_SPACER

logger = logging.getLogger(__name__)

FAILURE_THRESHOLD = 3
FAILURE_WINDOW_SECONDS = 60 * 60
ALERT_COOLDOWN_SECONDS = 60 * 60

# In-process only - resets on restart, which is already a natural
# "start fresh" point, same reasoning as not persisting this to SQLite.
_failure_times: dict[str, list[float]] = {}
_last_alert_at: dict[str, float] = {}

# A raw exception's str() can be a long single-line JSON dump (a real
# Gemini 503 body is ~200+ chars on its own) - direct user/mentor
# feedback: the admin group should get a short, scannable alert, not a
# wall of text. Truncated, not dropped - the full detail is still in
# the real log line record_failure() already writes.
_MAX_ERROR_MESSAGE_CHARS = 300

# One actionable hint per service - genuinely different next steps, not
# just filler. Falls back to a generic hint for any future service name
# added here without an update (record_failure/maybe_alert are already
# called with an arbitrary `service` string, not a closed enum).
_TODO_HINTS = {
    "Gemini": "Check the Gemini API key's quota/billing, or switch to a backup key if this is quota exhaustion.",
    "VirusTotal": "Check the VirusTotal API key's quota/status.",
    "Supabase": "Check the Supabase project's status and connection pool.",
}
_DEFAULT_TODO_HINT = "Check this service's own status page/dashboard."


def _format_alert(service: str, count: int, detail: str) -> str:
    now_local = datetime.now(timezone.utc) + timedelta(hours=DISPLAY_TIMEZONE_OFFSET_HOURS)
    when = f"{now_local.strftime('%d %b %Y, %I:%M %p')} (UTC{DISPLAY_TIMEZONE_OFFSET_HOURS:+d})"
    short_detail = detail if len(detail) <= _MAX_ERROR_MESSAGE_CHARS else (
        detail[:_MAX_ERROR_MESSAGE_CHARS].rstrip() + "…"
    )
    # Direct user spec (2026-09-11): the SAME box-drawing divider real
    # user-facing replies use the same blank disclaimer spacer as verdicts.
    # and each field's content sits on its own "- " bullet line below the
    # label, not inline after a colon.
    return (
        f"🚨 Error Detected\n"
        f"Type: {service}\n"
        f"Datetime: {when}\n"
        f"\n{DISCLAIMER_SPACER}\n\n"
        f"Error status: \n"
        f"- {count} failures in the last hour (bot is still degrading "
        f"gracefully via offline fallback)\n"
        f"Error message: \n"
        f"- {short_detail}\n"
        f"To do: \n"
        f"- {_TODO_HINTS.get(service, _DEFAULT_TODO_HINT)}"
    )


def record_failure(service: str, detail: str) -> None:
    """Call from any backend-calling code's except block, right where it
    already logs/degrades - this doesn't replace that, it's in addition
    to it. Pure and synchronous so it's safe to call from sync or async
    code without an event loop concern."""
    now = time.time()
    times = _failure_times.setdefault(service, [])
    times.append(now)
    cutoff = now - FAILURE_WINDOW_SECONDS
    _failure_times[service] = [t for t in times if t >= cutoff]
    logger.warning("[backend-failure] %s failed: %s (%d in the last hour)",
                    service, detail, len(_failure_times[service]))


async def maybe_alert(service: str, detail: str) -> None:
    """Fire-and-forget - call this right after record_failure(). Checks
    the rolling failure count and, if over threshold and not already
    alerted for this service within the cooldown, sends a real Telegram
    message. Never raises - an alerting failure must not compound an
    already-real backend failure."""
    now = time.time()
    count = len(_failure_times.get(service, []))
    if count < FAILURE_THRESHOLD:
        return
    if now - _last_alert_at.get(service, 0) < ALERT_COOLDOWN_SECONDS:
        return

    if not ADMIN_CHAT_ID or not TELEGRAM_BOT_TOKEN:
        logger.warning(
            "[backend-failure] %s has failed %d times in the last hour but "
            "ADMIN_CHAT_ID isn't set - no Telegram alert sent. Latest: %s",
            service, count, detail,
        )
        return

    _last_alert_at[service] = now
    text = _format_alert(service, count, detail)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": ADMIN_CHAT_ID, "text": text},
            )
    except Exception:                          # noqa: BLE001 - an alert failure must never crash the caller
        logger.exception("[backend-failure] failed to send admin alert for %s", service)
