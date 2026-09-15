"""
bot/detectors/text/online/gemini_retry.py
=============================================
Shared Gemini backup-key failover, used by both real call sites -
context_engine.py's unified analysis (private DM/business chat) and
this package's own llm.py (group-chat text scan). Added 2026-09-11
after real, repeated 429 RESOURCE_EXHAUSTED errors during actual live
Business chat traffic: the free tier caps at 5 requests/minute, and a
genuine back-and-forth conversation - each message triggering its own
Gemini call - blows through that in seconds.

GEMINI_API_KEY_BACKUP is optional, like GEMINI_API_KEY itself. Unset:
behavior is EXACTLY what it was before this file existed - any error
(429 included) propagates straight to the caller's own except block,
which already degrades to the offline fallback. Set: ONLY a 429
specifically triggers one retry against the backup key - every other
error (a genuine outage, a malformed request, a missing key entirely)
is NOT retried, since a second key wouldn't fix any of those.

Deliberately NOT a general-purpose rotation/pool scheme (more keys,
round-robin, etc.) - a single one-shot backup for the specific,
observed failure mode (primary key rate-limited), matching this
project's "manual for now, but this one narrow gap is worth automating"
call - see project memory for the fuller reasoning.
"""

from __future__ import annotations

import logging
import time

from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types

from bot.config.config import GEMINI_API_KEY, GEMINI_API_KEY_BACKUP

logger = logging.getLogger(__name__)

# Real, confirmed root cause of a live hang (2026-09-16): genai.Client()
# with no http_options leaves HttpOptions.timeout at its default of
# None, which the SDK passes straight through to its underlying httpx
# client as timeout=None - httpx's OWN convention for "no timeout at
# all" (confirmed by reading google.genai._api_client.get_timeout_in_seconds
# and BaseApiClient's request construction directly, not assumed). Every
# other outbound call in this codebase is bounded (network 10s, RDAP/TLS
# 8s, DNS 5s) - this was the one real exception, and it matters more
# here than anywhere else: a live Gemini "high demand" incident (500/503
# errors, confirmed happening in the SAME session as this fix, see
# health_alerts' own log) can just as easily mean the far end never
# responds at all instead of failing fast, and with no bound, the
# `except Exception` a few lines below every real caller already has
# never gets the chance to fire - the await just never returns. 25s is
# comfortably above every real successful call latency observed live
# (3-13s) while still being far below what would make a user think the
# bot crashed instead of just being slow.
GEMINI_TIMEOUT_MS = 25_000


def build_client(api_key: str | None) -> genai.Client | None:
    if not api_key:
        return None
    return genai.Client(
        api_key=api_key,
        http_options=genai_types.HttpOptions(timeout=GEMINI_TIMEOUT_MS),
    )


def build_clients() -> tuple[genai.Client | None, genai.Client | None]:
    """(primary, backup) - primary mirrors the existing `_client =
    genai.Client(...) if GEMINI_API_KEY else None` pattern each caller
    already has, so callers' own `if not _client:` early-return checks
    stay unchanged; only the actual generate_content call site needs
    to switch to generate_content_with_backup() below."""
    return build_client(GEMINI_API_KEY), build_client(GEMINI_API_KEY_BACKUP)


# --- Circuit breaker (2026-09-16, mentor/teammate spec) ----------------
#
# The 25s timeout above stops one hung call from blocking forever, but
# during a REAL sustained Gemini outage (the "high demand" 503s already
# observed live this same session), every single incoming message still
# pays that full timeout before falling back - a busy period could mean
# many users each waiting up to 25s just to be told the same thing:
# Gemini is down right now. This breaker skips the real call entirely
# once that pattern is confirmed, degrading straight to the offline
# fallback in effectively zero time until Gemini has had a chance to
# recover.
#
# Deliberately in-process, not persisted - resets on restart, same
# reasoning as health_alerts.py's own failure-window tracking (which
# this is a faster-reacting SIBLING of, not a replacement: health_alerts
# exists to tell a HUMAN about a pattern over an hour; this exists to
# stop paying a 25s tax on every request over the next 3 failures).
# CONSECUTIVE failures, not a rolling time window - three real
# successes at any point fully closes the breaker again, so a flaky-but-
# recovering service doesn't stay locked out.
CIRCUIT_FAILURE_THRESHOLD = 3
CIRCUIT_OPEN_SECONDS = 30

_consecutive_failures = 0
_circuit_open_until = 0.0


class GeminiCircuitOpenError(Exception):
    """Raised instead of even attempting a real call while the circuit
    is open. Both real callers (context_engine.py, llm.py) already have
    a broad `except Exception` around this call that degrades to the
    offline fallback - this needs no new except clause there to work,
    it just becomes another reason that fallback fires. Each caller
    special-cases THIS exception type only to skip re-recording a
    health_alerts failure for a request that was never actually
    attempted - see their own comments."""


def circuit_is_open() -> bool:
    return time.time() < _circuit_open_until


def _record_success() -> None:
    global _consecutive_failures, _circuit_open_until
    _consecutive_failures = 0
    _circuit_open_until = 0.0


def _record_failure() -> None:
    global _consecutive_failures, _circuit_open_until
    _consecutive_failures += 1
    if _consecutive_failures >= CIRCUIT_FAILURE_THRESHOLD:
        _circuit_open_until = time.time() + CIRCUIT_OPEN_SECONDS
        logger.warning(
            "[circuit-breaker] Gemini failed %d times in a row - skipping real "
            "calls for %ds, degrading straight to the offline fallback",
            _consecutive_failures, CIRCUIT_OPEN_SECONDS,
        )


async def _call_with_429_retry(primary_client, backup_client, **kwargs):
    """The original generate_content_with_backup body, unchanged -
    just renamed so the breaker above can wrap it without the 429/backup
    logic itself needing to know the breaker exists."""
    try:
        return await primary_client.aio.models.generate_content(**kwargs)
    except genai_errors.ClientError as error:
        if error.code == 429 and backup_client is not None:
            logger.warning(
                "Gemini primary key rate-limited (429) - retrying once with backup key"
            )
            return await backup_client.aio.models.generate_content(**kwargs)
        raise


async def generate_content_with_backup(primary_client, backup_client, **kwargs):
    """Same call shape/return value as client.aio.models.generate_content(
    **kwargs) - a caller with a working try/except around that call
    today can swap it for this with no other change. Raises exactly
    like a bare primary-client call would for anything except a 429
    with a configured backup_client, or GeminiCircuitOpenError while the
    breaker above is open."""
    if circuit_is_open():
        raise GeminiCircuitOpenError(
            f"Gemini circuit open after {_consecutive_failures} consecutive "
            f"failures - skipping this call, degrading straight to the offline fallback"
        )
    try:
        result = await _call_with_429_retry(primary_client, backup_client, **kwargs)
    except Exception:
        _record_failure()
        raise
    _record_success()
    return result
