"""
tests/test_health_alerts.py
==============================
Direct tests for bot/storage/health_alerts.py's threshold/cooldown
logic. The actual Telegram send is fully mocked - patching just
httpx.AsyncClient.post (leaving the real client's __aenter__/__aexit__
to run) measurably slowed these tests (~0.5s each, real TLS/connection
setup) even though .post itself never made a request; patching the
whole `async with httpx.AsyncClient(...) as client` context manager
avoids constructing a real client at all, matching the driver's own
real-network tests being the deliberate, sole exception to "tests don't
touch the network" in this codebase.
"""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bot.response import verdict_style
from bot.storage import health_alerts as alerts


@pytest.fixture(autouse=True)
def _reset_alert_state():
    """In-process module-level dicts - must reset between tests or an
    earlier test's recorded failures/cooldowns bleed into later ones,
    same class of bug already fixed once this session for subscription.py."""
    alerts._failure_times.clear()
    alerts._last_alert_at.clear()


def _mock_client_context(post_mock: AsyncMock) -> MagicMock:
    """A fake `async with httpx.AsyncClient(...) as client:` - client.post
    is post_mock, nothing real gets constructed."""
    mock_client = AsyncMock()
    mock_client.post = post_mock
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=False)
    return mock_cm


def test_below_threshold_does_not_alert():
    for _ in range(alerts.FAILURE_THRESHOLD - 1):
        alerts.record_failure("Gemini", "timeout")
    assert len(alerts._failure_times["Gemini"]) < alerts.FAILURE_THRESHOLD


def test_old_failures_outside_the_window_are_trimmed():
    # A failure from beyond FAILURE_WINDOW_SECONDS ago must not count
    # toward today's threshold - otherwise a handful of failures from
    # last week could quietly combine with a couple of fresh ones to
    # trigger an alert that doesn't reflect anything currently wrong.
    stale_time = time.time() - alerts.FAILURE_WINDOW_SECONDS - 60
    alerts._failure_times["VirusTotal"] = [stale_time] * alerts.FAILURE_THRESHOLD

    alerts.record_failure("VirusTotal", "fresh failure")  # triggers the trim

    assert len(alerts._failure_times["VirusTotal"]) == 1  # only the fresh one survived


@pytest.mark.asyncio
async def test_different_services_have_independent_thresholds_and_cooldowns(monkeypatch):
    # A Gemini outage reaching threshold must not trip VirusTotal's
    # alert, and vice versa - these are three unrelated systems with
    # nothing in common except sharing this one module.
    monkeypatch.setattr(alerts, "ADMIN_CHAT_ID", "12345")
    monkeypatch.setattr(alerts, "TELEGRAM_BOT_TOKEN", "fake-token")

    for _ in range(alerts.FAILURE_THRESHOLD):
        alerts.record_failure("Gemini", "quota exceeded")
    # VirusTotal has failed too, but only ONCE - well under threshold.
    alerts.record_failure("VirusTotal", "one-off timeout")

    mock_post = AsyncMock()
    with patch("bot.storage.health_alerts.httpx.AsyncClient", return_value=_mock_client_context(mock_post)):
        await alerts.maybe_alert("Gemini", "quota exceeded")
        await alerts.maybe_alert("VirusTotal", "one-off timeout")

    mock_post.assert_awaited_once()  # only Gemini's alert fired
    assert "Gemini" in mock_post.call_args.kwargs["json"]["text"]


@pytest.mark.asyncio
async def test_reaching_threshold_sends_a_real_alert_call(monkeypatch):
    monkeypatch.setattr(alerts, "ADMIN_CHAT_ID", "12345")
    monkeypatch.setattr(alerts, "TELEGRAM_BOT_TOKEN", "fake-token")

    for _ in range(alerts.FAILURE_THRESHOLD):
        alerts.record_failure("VirusTotal", "connection refused")

    mock_post = AsyncMock()
    with patch("bot.storage.health_alerts.httpx.AsyncClient", return_value=_mock_client_context(mock_post)):
        await alerts.maybe_alert("VirusTotal", "connection refused")

    mock_post.assert_awaited_once()
    call = mock_post.call_args
    assert "sendMessage" in call.args[0]
    assert call.kwargs["json"]["chat_id"] == "12345"
    assert "VirusTotal" in call.kwargs["json"]["text"]


@pytest.mark.asyncio
async def test_cooldown_prevents_repeat_alerts():
    with patch.object(alerts, "ADMIN_CHAT_ID", "12345"), \
         patch.object(alerts, "TELEGRAM_BOT_TOKEN", "fake-token"):
        for _ in range(alerts.FAILURE_THRESHOLD):
            alerts.record_failure("Supabase", "pool timeout")

        mock_post = AsyncMock()
        with patch("bot.storage.health_alerts.httpx.AsyncClient", return_value=_mock_client_context(mock_post)):
            await alerts.maybe_alert("Supabase", "pool timeout")
            assert mock_post.await_count == 1

            # Another failure right away must NOT trigger a second alert -
            # the cooldown is still active.
            alerts.record_failure("Supabase", "pool timeout again")
            await alerts.maybe_alert("Supabase", "pool timeout again")
            assert mock_post.await_count == 1


@pytest.mark.asyncio
async def test_missing_admin_chat_id_logs_but_never_raises(monkeypatch):
    monkeypatch.setattr(alerts, "ADMIN_CHAT_ID", None)
    for _ in range(alerts.FAILURE_THRESHOLD):
        alerts.record_failure("Gemini", "quota exceeded")

    # Must complete without raising even though no admin chat is configured.
    await alerts.maybe_alert("Gemini", "quota exceeded")


def test_format_alert_uses_the_short_scannable_template():
    # Direct user/mentor spec (2026-09-11): admin alerts should be a
    # short, scannable template (SECTION_DIVIDER, same as real user-facing
    # replies, plus one "- " bullet line per field), not a wall of raw
    # error text.
    text = alerts._format_alert("Gemini", 3, "503 UNAVAILABLE - high demand")

    assert text.startswith("🚨 Error Detected\nType: Gemini\nDatetime: ")
    assert f"\n{verdict_style.SECTION_DIVIDER}\n\n" in text
    assert "Error status: \n- 3 failures in the last hour" in text
    assert "Error message: \n- 503 UNAVAILABLE - high demand" in text
    assert "To do: \n-" in text


def test_format_alert_truncates_a_very_long_error_message():
    # A real Gemini error body is a long single-line JSON dump - must be
    # shortened, not dropped (the full text is still in the real log
    # line record_failure() writes separately).
    long_detail = "x" * 1000
    text = alerts._format_alert("Supabase", 5, long_detail)

    assert "x" * 1000 not in text
    assert "…" in text


@pytest.mark.asyncio
async def test_a_failed_alert_send_never_raises(monkeypatch):
    monkeypatch.setattr(alerts, "ADMIN_CHAT_ID", "12345")
    monkeypatch.setattr(alerts, "TELEGRAM_BOT_TOKEN", "fake-token")
    for _ in range(alerts.FAILURE_THRESHOLD):
        alerts.record_failure("Gemini", "quota exceeded")

    mock_post = AsyncMock(side_effect=ConnectionError("no network"))
    with patch("bot.storage.health_alerts.httpx.AsyncClient", return_value=_mock_client_context(mock_post)):
        await alerts.maybe_alert("Gemini", "quota exceeded")  # must not raise
