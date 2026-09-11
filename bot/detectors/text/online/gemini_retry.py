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

from google import genai
from google.genai import errors as genai_errors

from bot.config.config import GEMINI_API_KEY, GEMINI_API_KEY_BACKUP

logger = logging.getLogger(__name__)


def build_client(api_key: str | None) -> genai.Client | None:
    return genai.Client(api_key=api_key) if api_key else None


def build_clients() -> tuple[genai.Client | None, genai.Client | None]:
    """(primary, backup) - primary mirrors the existing `_client =
    genai.Client(...) if GEMINI_API_KEY else None` pattern each caller
    already has, so callers' own `if not _client:` early-return checks
    stay unchanged; only the actual generate_content call site needs
    to switch to generate_content_with_backup() below."""
    return build_client(GEMINI_API_KEY), build_client(GEMINI_API_KEY_BACKUP)


async def generate_content_with_backup(primary_client, backup_client, **kwargs):
    """Same call shape/return value as client.aio.models.generate_content(
    **kwargs) - a caller with a working try/except around that call
    today can swap it for this with no other change. Raises exactly
    like a bare primary-client call would for anything except a 429
    with a configured backup_client."""
    try:
        return await primary_client.aio.models.generate_content(**kwargs)
    except genai_errors.ClientError as error:
        if error.code == 429 and backup_client is not None:
            logger.warning(
                "Gemini primary key rate-limited (429) - retrying once with backup key"
            )
            return await backup_client.aio.models.generate_content(**kwargs)
        raise
