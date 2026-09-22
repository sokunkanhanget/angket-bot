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

Load-balanced primary pool (2026-09-22, reconsidered after real
evidence): GEMINI_API_KEY and GEMINI_API_KEY_TEST are round-robined
per call as co-primaries (see _next_primary), roughly doubling real
free-tier throughput before either one 429s - confirmed live this same
session that a single free-tier key saturates fast enough to
meaningfully skew a 50-message benchmark run. GEMINI_API_KEY_BACKUP
stays exactly what it always was: a one-shot retry on a 429 from
whichever pool key handled that specific call, not a third pool
member. This walks back this file's original "deliberately not a
rotation/pool scheme" stance from 2026-09-11 - that call made sense
with exactly 2 keys and one narrow observed failure mode; a third real
key changes the tradeoff.
"""

from __future__ import annotations

import logging
import time

from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types

from bot.config.config import GEMINI_API_KEY, GEMINI_API_KEY_BACKUP, GEMINI_API_KEY_TEST

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

# Real, confirmed root cause of the perceived slowness in production
# today (2026-09-22): google-genai's own Client has a SEPARATE, hidden
# retry layer underneath everything in this file - by default up to 5
# attempts (the original call plus 4 retries) with exponential backoff
# (1s -> 2s -> 4s -> 8s..., capped at 60s, plus jitter) on 408/429/
# 500/502/503, entirely inside genai.Client itself (google/genai/
# _api_client.py's own tenacity.AsyncRetrying, built from
# HttpRetryOptions - confirmed by reading the installed SDK directly,
# not assumed). GEMINI_TIMEOUT_MS above only bounds ONE such attempt's
# own HTTP timeout - it does nothing to bound how many attempts the SDK
# makes before finally raising. Measured live: a single real 503 cost
# 35s end to end before this fix, comfortably past GEMINI_TIMEOUT_MS,
# because the SDK silently retried internally first.
#
# This sat entirely BELOW this file's own retry/circuit-breaker design -
# _call_with_429_retry's "one retry against the backup key" and the
# circuit breaker's "3 consecutive failures" both assumed a single
# logical attempt costs roughly one timeout, not up to 5 stacked
# attempts each up to GEMINI_TIMEOUT_MS.
#
# attempts=2 (not 1 - reconsidered 2026-09-22 after weighing it
# explicitly): one bounded retry, not zero. A genuinely brief,
# self-resolving blip (network jitter, one momentary hiccup) is the
# more common real failure shape in normal operation - self-healing it
# turns an unnecessary degraded "Uncertain" verdict back into a real
# one, for a small, EXPLICITLY bounded cost (initial_delay/max_delay
# below - never the SDK's own default 60s max). During a genuinely
# SUSTAINED outage (today's real pattern - hours of recurring "high
# demand" 503s) this buys nothing and just adds that same small tax to
# every failing call before the same fallback fires either way - a real
# but minor cost, accepted for the brief-blip upside. Not a return to
# the original attempts=5/60s-max behavior that caused the 35s spike -
# still fully bounded, still far below GEMINI_TIMEOUT_MS's own ceiling,
# and still logged as a real failure by this file's own retry/breaker
# logic if the retry itself also fails.
_TAMED_SDK_RETRY = genai_types.HttpRetryOptions(attempts=2, initial_delay=1.0, max_delay=2.0)


def build_client(api_key: str | None) -> genai.Client | None:
    if not api_key:
        return None
    return genai.Client(
        api_key=api_key,
        http_options=genai_types.HttpOptions(
            timeout=GEMINI_TIMEOUT_MS, retry_options=_TAMED_SDK_RETRY,
        ),
    )


def build_clients() -> tuple[list[genai.Client], genai.Client | None]:
    """(primary_pool, backup) - primary_pool holds every configured
    co-primary key (GEMINI_API_KEY, GEMINI_API_KEY_TEST), unset ones
    filtered out, so `if not _primary_pool:` at a caller (an empty list
    is falsy, same as the old single `None` client) still correctly
    means "no primary key configured at all". Only the actual
    generate_content call site needs to switch to
    generate_content_with_backup() below, which round-robins the pool
    internally - callers just pass the pool through unchanged."""
    primary_pool = [c for c in (build_client(GEMINI_API_KEY), build_client(GEMINI_API_KEY_TEST)) if c is not None]
    return primary_pool, build_client(GEMINI_API_KEY_BACKUP)


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


_rr_index = 0


def _next_primary(primary_pool: list[genai.Client]):
    """Round-robins primary_pool per call - a plain incrementing counter,
    not per-key call counts, since every real call site here already
    goes through this one function (no way for the pool to get
    unevenly hit from outside it). Module-level and unsynchronized:
    a rare interleaved read under real asyncio concurrency just means
    two calls occasionally land on the same key instead of strictly
    alternating - fine, this is load-spreading, not a correctness
    requirement."""
    global _rr_index
    if not primary_pool:
        return None
    client = primary_pool[_rr_index % len(primary_pool)]
    _rr_index += 1
    return client


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


async def generate_content_with_backup(primary_pool, backup_client, **kwargs):
    """Same call shape/return value as client.aio.models.generate_content(
    **kwargs) - a caller with a working try/except around that call
    today can swap it for this with no other change beyond passing the
    pool (build_clients()' first element) instead of a single client.
    Raises exactly like a bare primary-client call would for anything
    except a 429 with a configured backup_client, or
    GeminiCircuitOpenError while the breaker above is open."""
    if circuit_is_open():
        raise GeminiCircuitOpenError(
            f"Gemini circuit open after {_consecutive_failures} consecutive "
            f"failures - skipping this call, degrading straight to the offline fallback"
        )
    primary_client = _next_primary(primary_pool)
    try:
        result = await _call_with_429_retry(primary_client, backup_client, **kwargs)
    except Exception:
        _record_failure()
        raise
    _record_success()
    return result
