"""
tests/test_gemini_embed.py
=============================
Direct unit coverage for bot/detectors/text/online/gemini_embed.py's
embed_gemini() - bge-m3's second-tier fallback embedding source
(2026-09-21). Mocked, not skip-gated on live reachability like
bge_m3_embed.py's own tests - Gemini's API is a real, always-"reachable"
paid/quota'd endpoint, not a local dev dependency, matching how every
other Gemini call site in this project is tested (see test_llm_analyzer.py).
"""

import asyncio
from unittest.mock import AsyncMock, patch

from bot.detectors.text.online import gemini_embed


def _fake_client(values=None, raise_error: Exception | None = None):
    if raise_error is not None:
        embed_content = AsyncMock(side_effect=raise_error)
    else:
        fake_response = type("FakeResponse", (), {
            "embeddings": [type("Embedding", (), {"values": values})()] if values is not None else [],
        })()
        embed_content = AsyncMock(return_value=fake_response)
    return type("FakeClient", (), {"aio": type("Aio", (), {"models": type("Models", (), {
        "embed_content": embed_content,
    })()})()})()


def test_embed_gemini_returns_none_when_no_client_configured():
    # No GEMINI_API_KEY_EMBEDDING - the real state until someone sets it.
    with patch.object(gemini_embed, "_client", None):
        result = asyncio.run(gemini_embed.embed_gemini("test message"))

    assert result is None


def test_embed_gemini_returns_a_real_vector():
    fake_client = _fake_client(values=[0.1, 0.2, 0.3])

    with patch.object(gemini_embed, "_client", fake_client):
        result = asyncio.run(gemini_embed.embed_gemini("urgent, verify your account"))

    assert result == [0.1, 0.2, 0.3]
    fake_client.aio.models.embed_content.assert_awaited_once()


def test_embed_gemini_returns_none_on_empty_embeddings_list():
    fake_client = _fake_client(values=None)  # response.embeddings == []

    with patch.object(gemini_embed, "_client", fake_client):
        result = asyncio.run(gemini_embed.embed_gemini("test"))

    assert result is None


def test_embed_gemini_returns_none_on_any_api_failure():
    # Same defensive shape as bge_m3_embed.py's embed_bge_m3 - must
    # degrade, never crash the caller.
    fake_client = _fake_client(raise_error=RuntimeError("quota exceeded"))

    with patch.object(gemini_embed, "_client", fake_client):
        result = asyncio.run(gemini_embed.embed_gemini("test"))

    assert result is None


# --- Own circuit breaker (2026-09-22, found via networking review) -----
# Separate state from gemini_retry.py's breaker (different key/quota) -
# see tests/conftest.py's _reset_gemini_circuit_breaker fixture for why
# this needs its own reset between tests too.

def test_circuit_opens_after_threshold_consecutive_failures():
    fake_client = _fake_client(raise_error=RuntimeError("outage"))

    with patch.object(gemini_embed, "_client", fake_client):
        for _ in range(gemini_embed._CIRCUIT_FAILURE_THRESHOLD):
            asyncio.run(gemini_embed.embed_gemini("test"))

    assert gemini_embed._circuit_is_open() is True


def test_open_circuit_skips_the_real_call_entirely():
    fake_client = _fake_client(raise_error=RuntimeError("outage"))

    with patch.object(gemini_embed, "_client", fake_client):
        for _ in range(gemini_embed._CIRCUIT_FAILURE_THRESHOLD):
            asyncio.run(gemini_embed.embed_gemini("test"))
        fake_client.aio.models.embed_content.reset_mock()

        result = asyncio.run(gemini_embed.embed_gemini("test"))

    assert result is None
    fake_client.aio.models.embed_content.assert_not_awaited()


def test_a_real_success_resets_the_breaker():
    failing_client = _fake_client(raise_error=RuntimeError("outage"))
    with patch.object(gemini_embed, "_client", failing_client):
        for _ in range(gemini_embed._CIRCUIT_FAILURE_THRESHOLD - 1):
            asyncio.run(gemini_embed.embed_gemini("test"))

    succeeding_client = _fake_client(values=[0.1, 0.2])
    with patch.object(gemini_embed, "_client", succeeding_client):
        asyncio.run(gemini_embed.embed_gemini("test"))

    assert gemini_embed._circuit_is_open() is False
    assert gemini_embed._consecutive_failures == 0
