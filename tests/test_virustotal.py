"""
tests/test_virustotal.py
===========================
Direct unit coverage for bot/detectors/file/online/virustotal.py's
scan_vt_hash() - previously untested directly (only ever exercised via
handler tests that mock scan_file/scan_vt_hash out entirely). Focuses
on the `checked` field this session added: a confirmed "VirusTotal has
never seen this hash" (checked=True, found=False) must be
distinguishable from "VirusTotal itself couldn't be reached"
(checked=False) - before this, both were the exact same
{"found": False}, which read as a real (if weak) safety signal during
an actual outage.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import vt

from bot.detectors.file.online.virustotal import scan_vt_hash


def _fake_client(file_obj=None, raise_error: Exception | None = None):
    """A MagicMock standing in for vt.Client, usable as `async with
    vt.Client(...) as client`."""
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    if raise_error is not None:
        client.get_object_async = AsyncMock(side_effect=raise_error)
    else:
        client.get_object_async = AsyncMock(return_value=file_obj)
    return client


@pytest.mark.asyncio
async def test_real_hit_reports_checked_and_found():
    file_obj = MagicMock()
    file_obj.last_analysis_stats = {"malicious": 3, "suspicious": 1, "harmless": 70, "undetected": 1}
    file_obj.last_analysis_results = {
        "Microsoft": {"category": "malicious", "result": "Trojan"},
        "Kaspersky": {"category": "undetected", "result": None},
        "BitDefender": {"category": "undetected", "result": None},
    }

    with patch("bot.detectors.file.online.virustotal.vt.Client", return_value=_fake_client(file_obj=file_obj)):
        result = await scan_vt_hash("a" * 64)

    assert result["checked"] is True
    assert result["found"] is True
    assert result["malicious"] == 3
    assert result["top_engines"]["Microsoft"] == "Detected (Trojan)"


@pytest.mark.asyncio
async def test_confirmed_not_found_is_checked_true_found_false():
    # A real, confirmed answer: VT has genuinely never seen this hash.
    not_found = vt.APIError("NotFoundError", "not found")

    with patch("bot.detectors.file.online.virustotal.vt.Client", return_value=_fake_client(raise_error=not_found)):
        result = await scan_vt_hash("b" * 64)

    assert result == {"checked": True, "found": False}


@pytest.mark.asyncio
async def test_other_api_error_is_checked_false_not_confirmed_not_found():
    # Real bug this fixes: an auth/quota/rate-limit APIError used to come
    # back with the exact same shape as a confirmed NotFoundError -
    # indistinguishable from "VirusTotal has genuinely never seen this",
    # when the truth is VirusTotal was never actually asked successfully.
    quota_error = vt.APIError("QuotaExceededError", "quota exceeded")

    with patch("bot.detectors.file.online.virustotal.vt.Client", return_value=_fake_client(raise_error=quota_error)):
        result = await scan_vt_hash("c" * 64)

    assert result["checked"] is False
    assert result["found"] is False
    assert "quota exceeded" in result["error"]


@pytest.mark.asyncio
async def test_raw_connection_failure_is_checked_false_not_an_uncaught_crash():
    # Real bug this fixes: a connection-level failure (network down, DNS,
    # timeout - anything below vt.APIError) used to propagate straight
    # out of this function uncaught, forcing every caller to guard
    # against it separately instead of getting one honest, consistent
    # "VT couldn't be checked" answer.
    with patch(
        "bot.detectors.file.online.virustotal.vt.Client",
        return_value=_fake_client(raise_error=ConnectionError("network unreachable")),
    ):
        result = await scan_vt_hash("d" * 64)

    assert result["checked"] is False
    assert result["found"] is False
    assert "network unreachable" in result["error"]
