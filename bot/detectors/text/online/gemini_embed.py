"""
bot/detectors/text/online/gemini_embed.py
=============================================
Second-tier fallback embedding source for the scam-pattern similarity
match, live as of 2026-09-21. bge-m3 (hosted on Modal - see
bge_m3_embed.py) stays the primary, better-validated model; this only
ever fires when bge-m3 itself is unreachable (Modal down, a cold-start
timeout, etc.) - see scam_patterns.py's nearest_scam_pattern_live() for
the actual 3-tier chain (bge-m3 -> this -> the hashed scheme).

Uses GEMINI_API_KEY_EMBEDDING (bot/config/config.py) - a key already
sitting in the real .env, unused until now - deliberately separate from
GEMINI_API_KEY (the main reasoning calls), so embedding call volume
never competes with the primary Gemini quota this project already has
recurring 429/rate-limit pain with (see gemini_retry.py's own docstring).

Verified against the real installed google-genai SDK directly (not
assumed): AsyncModels.embed_content(*, model, contents, config) ->
EmbedContentResponse, and response.embeddings[0].values is the real
dense vector - genai.types.EmbedContentConfig(task_type=...) is a real,
supported field.
"""

from __future__ import annotations

import logging
import time

from google.genai import types as genai_types

from bot.config.config import GEMINI_API_KEY_EMBEDDING, GEMINI_EMBED_MODEL
from bot.detectors.text.online.gemini_retry import build_client

logger = logging.getLogger(__name__)

_client = build_client(GEMINI_API_KEY_EMBEDDING)

# Own circuit breaker (2026-09-22, found via networking review), separate
# state from gemini_retry.py's - this call uses GEMINI_API_KEY_EMBEDDING,
# a different key/quota from the main reasoning path, so a reasoning
# outage must never trip this breaker and vice versa. build_client()
# already bounds each call to 25s (GEMINI_TIMEOUT_MS), so a sustained
# embedding-API outage without this would still cost every scam-pattern
# check a full 25s before falling through to the hashed scheme - same
# reasoning gemini_retry.py's own breaker docstring gives for the main
# path. Same thresholds for consistency, not because they're shared state.
_CIRCUIT_FAILURE_THRESHOLD = 3
_CIRCUIT_OPEN_SECONDS = 30
_consecutive_failures = 0
_circuit_open_until = 0.0


def _circuit_is_open() -> bool:
    return time.time() < _circuit_open_until


def _record_success() -> None:
    global _consecutive_failures, _circuit_open_until
    _consecutive_failures = 0
    _circuit_open_until = 0.0


def _record_failure() -> None:
    global _consecutive_failures, _circuit_open_until
    _consecutive_failures += 1
    if _consecutive_failures >= _CIRCUIT_FAILURE_THRESHOLD:
        _circuit_open_until = time.time() + _CIRCUIT_OPEN_SECONDS
        logger.warning(
            "[circuit-breaker] Gemini embedding failed %d times in a row - "
            "skipping real calls for %ds, degrading straight to the hashed scheme",
            _consecutive_failures, _CIRCUIT_OPEN_SECONDS,
        )


async def embed_gemini(text: str) -> list[float] | None:
    """Real embedding via Gemini's own embed_content endpoint. Returns
    None on ANY failure (no key configured, network down, quota
    exhausted, malformed response, circuit open, etc.) - callers must
    treat this as "unavailable, fall back further down the chain", never
    crash on it. Same defensive shape as bge_m3_embed.py's embed_bge_m3()
    - a bare except, no partial/best-effort result."""
    if _client is None or _circuit_is_open():
        return None
    try:
        response = await _client.aio.models.embed_content(
            model=GEMINI_EMBED_MODEL,
            contents=text,
            config=genai_types.EmbedContentConfig(task_type="SEMANTIC_SIMILARITY"),
        )
        embeddings = response.embeddings
        if not embeddings:
            _record_failure()
            return None
        values = embeddings[0].values
        if not values:
            _record_failure()
            return None
        _record_success()
        return list(values)
    except Exception:                          # noqa: BLE001 - unavailable embedding source must degrade, not crash
        _record_failure()
        return None
