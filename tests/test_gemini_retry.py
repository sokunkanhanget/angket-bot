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

from bot.detectors.text.online import gemini_retry
from bot.detectors.text.online.gemini_retry import (
    CIRCUIT_FAILURE_THRESHOLD,
    GeminiCircuitOpenError,
    circuit_is_open,
    generate_content_with_backup,
)


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

    result = await generate_content_with_backup([primary], backup, model="x", contents="y")

    assert result == "primary result"
    backup.aio.models.generate_content.assert_not_awaited()


@pytest.mark.asyncio
async def test_retries_with_backup_on_a_429_when_backup_is_configured():
    primary = AsyncMock()
    primary.aio.models.generate_content = AsyncMock(side_effect=_fake_429())
    backup = AsyncMock()
    backup.aio.models.generate_content = AsyncMock(return_value="backup result")

    result = await generate_content_with_backup([primary], backup, model="x", contents="y")

    assert result == "backup result"
    # Same call shape/kwargs went to both - a caller shouldn't need to
    # special-case what the backup key receives.
    primary.aio.models.generate_content.assert_awaited_once_with(model="x", contents="y")
    backup.aio.models.generate_content.assert_awaited_once_with(model="x", contents="y")


@pytest.mark.asyncio
async def test_round_robins_between_pool_clients():
    # 2026-09-22 load-balancer: GEMINI_API_KEY and GEMINI_API_KEY_TEST
    # are co-primaries now, not a single client - each call should
    # alternate through the pool instead of always hitting the first one.
    client_a = AsyncMock()
    client_a.aio.models.generate_content = AsyncMock(return_value="from a")
    client_b = AsyncMock()
    client_b.aio.models.generate_content = AsyncMock(return_value="from b")
    pool = [client_a, client_b]

    first = await generate_content_with_backup(pool, None)
    second = await generate_content_with_backup(pool, None)
    third = await generate_content_with_backup(pool, None)

    assert (first, second, third) == ("from a", "from b", "from a")


@pytest.mark.asyncio
async def test_an_empty_pool_raises_same_as_the_old_unconfigured_client():
    # build_clients() returns [] (not None) when no primary key is
    # configured at all - callers' `if not _primary_pool:` guard already
    # handles that before ever reaching here, but this call itself must
    # still fail loudly (not silently no-op) if it's ever reached anyway.
    with pytest.raises(AttributeError):
        await generate_content_with_backup([], None)


@pytest.mark.asyncio
async def test_a_429_propagates_when_no_backup_is_configured():
    primary = AsyncMock()
    primary.aio.models.generate_content = AsyncMock(side_effect=_fake_429())

    with pytest.raises(genai_errors.ClientError):
        await generate_content_with_backup([primary], None, model="x", contents="y")


@pytest.mark.asyncio
async def test_a_non_429_error_is_never_retried_even_with_a_backup_configured():
    # A backup key wouldn't fix a genuine outage or a malformed request
    # - only quota/rate-limit exhaustion is worth a second try.
    primary = AsyncMock()
    primary.aio.models.generate_content = AsyncMock(side_effect=_fake_400())
    backup = AsyncMock()
    backup.aio.models.generate_content = AsyncMock(return_value="backup result")

    with pytest.raises(genai_errors.ClientError):
        await generate_content_with_backup([primary], backup, model="x", contents="y")

    backup.aio.models.generate_content.assert_not_awaited()


# --- build_client's real HTTP timeout (2026-09-16 regression) ----------
# Real, confirmed live bug: genai.Client() with no http_options left
# HttpOptions.timeout at its default of None, which the SDK passes
# straight through to its own httpx client as timeout=None - httpx's
# convention for "no timeout at all". A live Gemini "high demand"
# incident that hangs instead of failing fast used to stall the whole
# reply forever - no exception ever raised, so the existing
# `except Exception` fallback in every real caller never got the chance
# to fire.

def test_build_client_sets_a_real_http_timeout():
    from bot.detectors.text.online.gemini_retry import GEMINI_TIMEOUT_MS, build_client

    client = build_client("fake-key-for-this-test")

    assert client is not None
    assert client._api_client._http_options.timeout == GEMINI_TIMEOUT_MS


def test_build_client_returns_none_for_no_key():
    from bot.detectors.text.online.gemini_retry import build_client

    assert build_client(None) is None
    assert build_client("") is None


def test_build_client_tames_the_sdk_own_hidden_retry_layer():
    # Real, confirmed root cause of a live 35s single-call latency spike
    # (2026-09-22): genai.Client has its OWN retry layer underneath
    # everything else in this file - by default up to 5 attempts with
    # exponential backoff (up to 60s max delay) on 408/429/500/502/503,
    # entirely separate from this file's own _call_with_429_retry/circuit
    # breaker. GEMINI_TIMEOUT_MS only bounds ONE such attempt, not how
    # many the SDK makes before finally raising.
    #
    # Explicitly tamed, not disabled (weighed both directly with the
    # user, 2026-09-22): one bounded retry (attempts=2), tight delay
    # (max 2s, never the SDK's own 60s default) - self-heals a genuine
    # brief blip into a real verdict instead of an unnecessary degraded
    # one, while staying far below the original pathological 35s spike.
    from bot.detectors.text.online.gemini_retry import build_client

    client = build_client("fake-key-for-this-test")

    assert client is not None
    retry_options = client._api_client._http_options.retry_options
    assert retry_options.attempts == 2
    assert retry_options.max_delay == 2.0
    assert client._api_client._async_retry.stop.max_attempt_number == 2


@pytest.mark.asyncio
async def test_a_hung_gemini_server_times_out_instead_of_hanging_forever():
    # The real live repro, reduced to a minimal case: a server that
    # accepts the connection but never sends a response. Without
    # build_client's http_options fix, this would hang for the full
    # server-side delay (or forever) instead of raising.
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from bot.detectors.text.online.gemini_retry import build_client

    class _HangsForever(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            time.sleep(30)  # far past the client's own bound below

    server = ThreadingHTTPServer(("127.0.0.1", 0), _HangsForever)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        client = build_client("fake-key")
        # A short bound for a fast test - build_client's own real
        # GEMINI_TIMEOUT_MS (25s) is proven separately above; this proves
        # the mechanism actually fires, not the specific number.
        client._api_client._http_options.timeout = 1_000
        client._api_client._http_options.base_url = f"http://127.0.0.1:{port}"

        started = time.perf_counter()
        with pytest.raises(Exception):
            await client.aio.models.generate_content(model="gemini-3.6-flash", contents="hi")
        elapsed = time.perf_counter() - started
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert elapsed < 5.0  # nowhere near the server's 30s hang


# --- Circuit breaker (2026-09-16, mentor/teammate spec) -----------------
# After CIRCUIT_FAILURE_THRESHOLD consecutive failures, skip real calls
# entirely for CIRCUIT_OPEN_SECONDS instead of paying GEMINI_TIMEOUT_MS
# on every request during a real sustained outage.

def _failing_client() -> AsyncMock:
    client = AsyncMock()
    client.aio.models.generate_content = AsyncMock(side_effect=RuntimeError("simulated outage"))
    return client


def _working_client(result="ok") -> AsyncMock:
    client = AsyncMock()
    client.aio.models.generate_content = AsyncMock(return_value=result)
    return client


@pytest.mark.asyncio
async def test_circuit_stays_closed_below_the_threshold():
    client = _failing_client()
    for _ in range(CIRCUIT_FAILURE_THRESHOLD - 1):
        with pytest.raises(RuntimeError):
            await generate_content_with_backup([client], None)

    assert circuit_is_open() is False


@pytest.mark.asyncio
async def test_circuit_opens_after_threshold_consecutive_failures():
    client = _failing_client()
    for _ in range(CIRCUIT_FAILURE_THRESHOLD):
        with pytest.raises(RuntimeError):
            await generate_content_with_backup([client], None)

    assert circuit_is_open() is True


@pytest.mark.asyncio
async def test_open_circuit_skips_the_real_call_entirely():
    client = _failing_client()
    for _ in range(CIRCUIT_FAILURE_THRESHOLD):
        with pytest.raises(RuntimeError):
            await generate_content_with_backup([client], None)

    client.aio.models.generate_content.reset_mock()

    with pytest.raises(GeminiCircuitOpenError):
        await generate_content_with_backup([client], None)

    # The whole point: no real network call was made this time.
    client.aio.models.generate_content.assert_not_called()


@pytest.mark.asyncio
async def test_a_success_resets_the_failure_count():
    client = _failing_client()
    for _ in range(CIRCUIT_FAILURE_THRESHOLD - 1):
        with pytest.raises(RuntimeError):
            await generate_content_with_backup([client], None)

    working = _working_client()
    result = await generate_content_with_backup([working], None)
    assert result == "ok"

    # One more failure now must NOT open the circuit - the success above
    # cleared the streak, so this is failure #1 again, not #3.
    with pytest.raises(RuntimeError):
        await generate_content_with_backup([_failing_client()], None)

    assert circuit_is_open() is False


@pytest.mark.asyncio
async def test_circuit_closes_again_after_the_open_window_expires(monkeypatch):
    client = _failing_client()
    for _ in range(CIRCUIT_FAILURE_THRESHOLD):
        with pytest.raises(RuntimeError):
            await generate_content_with_backup([client], None)
    assert circuit_is_open() is True

    # Simulate the open window having already elapsed, rather than a
    # real sleep - same technique this project already uses for other
    # time-window tests (e.g. test_subscription.py's day-rollover test).
    monkeypatch.setattr(gemini_retry, "_circuit_open_until", 0.0)

    assert circuit_is_open() is False
    result = await generate_content_with_backup([_working_client("recovered")], None)
    assert result == "recovered"


@pytest.mark.asyncio
async def test_429_retry_against_backup_key_still_works_with_the_breaker_present():
    # Regression: the breaker wraps the existing 429/backup-key retry,
    # not the other way around - a successful backup-key retry must
    # still count as an overall SUCCESS (resets the failure streak),
    # not a failure.
    primary = AsyncMock()
    primary.aio.models.generate_content = AsyncMock(side_effect=_fake_429())
    backup = _working_client("from backup")

    result = await generate_content_with_backup([primary], backup)

    assert result == "from backup"
    assert circuit_is_open() is False
