"""
tests/test_gemini_retry.py
=============================
Direct tests for bot/detectors/text/online/gemini_retry.py - the
shared Gemini backup-key failover added 2026-09-11 after real,
repeated 429 RESOURCE_EXHAUSTED errors during actual live Business
chat traffic (free tier: 5 requests/minute).
"""

from unittest.mock import AsyncMock

import pytest
from google.genai import errors as genai_errors

from bot.detectors.text.online.gemini_retry import generate_content_with_backup


def _fake_429() -> genai_errors.ClientError:
    return genai_errors.ClientError(429, {"error": {"message": "quota exceeded"}})


def _fake_400() -> genai_errors.ClientError:
    return genai_errors.ClientError(400, {"error": {"message": "bad request"}})


@pytest.mark.asyncio
async def test_returns_primary_result_on_success():
    primary = AsyncMock()
    primary.aio.models.generate_content = AsyncMock(return_value="primary result")
    backup = AsyncMock()
    backup.aio.models.generate_content = AsyncMock(return_value="backup result")

    result = await generate_content_with_backup(primary, backup, model="x", contents="y")

    assert result == "primary result"
    backup.aio.models.generate_content.assert_not_awaited()


@pytest.mark.asyncio
async def test_retries_with_backup_on_a_429_when_backup_is_configured():
    primary = AsyncMock()
    primary.aio.models.generate_content = AsyncMock(side_effect=_fake_429())
    backup = AsyncMock()
    backup.aio.models.generate_content = AsyncMock(return_value="backup result")

    result = await generate_content_with_backup(primary, backup, model="x", contents="y")

    assert result == "backup result"
    # Same call shape/kwargs went to both - a caller shouldn't need to
    # special-case what the backup key receives.
    primary.aio.models.generate_content.assert_awaited_once_with(model="x", contents="y")
    backup.aio.models.generate_content.assert_awaited_once_with(model="x", contents="y")


@pytest.mark.asyncio
async def test_a_429_propagates_when_no_backup_is_configured():
    primary = AsyncMock()
    primary.aio.models.generate_content = AsyncMock(side_effect=_fake_429())

    with pytest.raises(genai_errors.ClientError):
        await generate_content_with_backup(primary, None, model="x", contents="y")


@pytest.mark.asyncio
async def test_a_non_429_error_is_never_retried_even_with_a_backup_configured():
    # A backup key wouldn't fix a genuine outage or a malformed request
    # - only quota/rate-limit exhaustion is worth a second try.
    primary = AsyncMock()
    primary.aio.models.generate_content = AsyncMock(side_effect=_fake_400())
    backup = AsyncMock()
    backup.aio.models.generate_content = AsyncMock(return_value="backup result")

    with pytest.raises(genai_errors.ClientError):
        await generate_content_with_backup(primary, backup, model="x", contents="y")

    backup.aio.models.generate_content.assert_not_awaited()
