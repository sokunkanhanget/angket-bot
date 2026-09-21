"""
tests/test_scam_patterns_gemini.py
=====================================
Tests for nearest_scam_pattern_live()'s Gemini-embedding SECOND-TIER
fallback (2026-09-21) - specifically the case bge-m3's own test file
(test_scam_patterns_bge_m3.py) deliberately isolates away: bge-m3 down
but Gemini's embedding API still reachable. Mocked throughout (not
skip-gated on live reachability) - Gemini's API is a real, always-
"reachable" paid/quota'd endpoint in CI, not a local dev dependency like
Ollama/Modal, matching how every other Gemini call site in this project
is tested (test_llm_analyzer.py).
"""

from unittest.mock import AsyncMock

import pytest

from bot.detectors.text.offline import scam_patterns
from bot.detectors.text.online import gemini_embed


@pytest.fixture(autouse=True)
def _reset_indexes():
    """Both module-level index caches must not leak between tests."""
    scam_patterns._bge_m3_index = None
    scam_patterns._gemini_index = None
    yield
    scam_patterns._bge_m3_index = None
    scam_patterns._gemini_index = None


def _fake_gemini_client(vector_for_text):
    """A fake genai client whose embed_content returns a DIFFERENT fixed
    vector per input text (via a text -> vector mapping), so a query can
    be made to score highest against one specific corpus category by
    construction, not by real semantic similarity - this test proves the
    WIRING (which tier answered, right threshold picked), not Gemini's
    own embedding quality (that needs real calibration data - see
    GEMINI_EMBED_PATTERN_THRESHOLD's own "placeholder" comment).

    Must use AsyncMock, not a plain async function, as the class
    attribute below - a plain function assigned to a class dict binds as
    an instance method (implicit `self`), which breaks a keyword-only
    signature. AsyncMock isn't a descriptor, so it stays unbound - same
    pattern test_gemini_embed.py already uses."""
    async def _make_response(*, model, contents, config=None):
        values = vector_for_text(contents)
        embedding = type("Embedding", (), {"values": values})()
        return type("FakeResponse", (), {"embeddings": [embedding]})()

    embed_content = AsyncMock(side_effect=_make_response)
    return type("FakeClient", (), {"aio": type("Aio", (), {"models": type("Models", (), {
        "embed_content": embed_content,
    })()})()})()


@pytest.mark.asyncio
async def test_bge_m3_down_falls_through_to_gemini_and_reports_it(monkeypatch):
    # The exact case test_scam_patterns_bge_m3.py deliberately neutralizes
    # away - bge-m3 unreachable, Gemini embedding tier picks up the call.
    monkeypatch.setattr("bot.config.config.USE_BGE_M3_EMBEDDINGS", True)
    monkeypatch.setattr("bot.detectors.text.online.bge_m3_embed.OLLAMA_URL", "http://localhost:1")

    # Every corpus row and the query all get the SAME vector, so the
    # query trivially scores 1.0 against everything - real similarity
    # quality isn't the point here, only "did the Gemini tier answer and
    # get correctly reported".
    fake_client = _fake_gemini_client(lambda text: [1.0, 0.0, 0.0])
    monkeypatch.setattr(gemini_embed, "_client", fake_client)

    hits, source = await scam_patterns.nearest_scam_pattern_live("some text", k=1)

    assert source == "gemini"
    assert hits
    assert scam_patterns._bge_m3_index is None  # bge-m3 index build genuinely failed, never got set
    assert scam_patterns._gemini_index is not None  # Gemini's own index got built instead


@pytest.mark.asyncio
async def test_bge_m3_off_still_tries_gemini_before_hashed(monkeypatch):
    # Flag OFF (not "failed") must be treated the same as "bge-m3 didn't
    # answer" for fallback purposes - the whole point of a resilience
    # chain is "use the best available live embedding", not "only
    # fall back on an actual error".
    monkeypatch.setattr("bot.config.config.USE_BGE_M3_EMBEDDINGS", False)
    fake_client = _fake_gemini_client(lambda text: [1.0, 0.0, 0.0])
    monkeypatch.setattr(gemini_embed, "_client", fake_client)

    hits, source = await scam_patterns.nearest_scam_pattern_live("some text", k=1)

    assert source == "gemini"
    assert scam_patterns._bge_m3_index is None  # never even attempted - flag was off


@pytest.mark.asyncio
async def test_both_bge_m3_and_gemini_down_falls_all_the_way_to_hashed(monkeypatch):
    monkeypatch.setattr("bot.config.config.USE_BGE_M3_EMBEDDINGS", True)
    monkeypatch.setattr("bot.detectors.text.online.bge_m3_embed.OLLAMA_URL", "http://localhost:1")
    monkeypatch.setattr(gemini_embed, "_client", None)
    text = "free bitcoin now, click nowhere"

    live_hits, source = await scam_patterns.nearest_scam_pattern_live(text, k=1)
    direct_hits = scam_patterns.nearest_scam_pattern(text, k=1)

    assert source == "hashed"
    assert live_hits == direct_hits


@pytest.mark.asyncio
async def test_gemini_index_built_once_and_reused(monkeypatch):
    monkeypatch.setattr("bot.config.config.USE_BGE_M3_EMBEDDINGS", False)
    fake_client = _fake_gemini_client(lambda text: [1.0, 0.0, 0.0])
    monkeypatch.setattr(gemini_embed, "_client", fake_client)

    await scam_patterns.nearest_scam_pattern_live("message one", k=1)
    index_after_first_call = scam_patterns._gemini_index
    assert index_after_first_call is not None

    await scam_patterns.nearest_scam_pattern_live("message two", k=1)
    assert scam_patterns._gemini_index is index_after_first_call  # not rebuilt
