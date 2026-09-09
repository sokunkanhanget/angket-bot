"""
tests/test_bge_m3_embed.py
=============================
cosine_similarity() is pure - always runs, no network. embed_bge_m3()
needs a real Ollama instance with bge-m3 pulled - most environments
(a teammate's machine, CI, a future session) won't have this, so that
part is skipped cleanly rather than failing the suite, preserving this
project's "tests need no real network" invariant. Ran for real, live,
while building this feature (a real local Ollama+bge-m3 was available
in that environment) - see the session notes for the actual numbers.
"""

import httpx
import pytest

from bot.detectors.text.online.bge_m3_embed import cosine_similarity, embed_bge_m3
from bot.config.config import OLLAMA_URL


def _ollama_reachable() -> bool:
    try:
        httpx.get(f"{OLLAMA_URL}/api/version", timeout=2)
        return True
    except Exception:
        return False


def test_cosine_similarity_identical_vectors():
    v = [1.0, 2.0, 3.0]
    assert cosine_similarity(v, v) == pytest.approx(1.0)


def test_cosine_similarity_orthogonal_vectors():
    assert cosine_similarity([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)


def test_cosine_similarity_handles_mismatched_or_empty_input():
    assert cosine_similarity([], [1.0]) == 0.0
    assert cosine_similarity([1.0], [1.0, 2.0]) == 0.0
    assert cosine_similarity([0.0, 0.0], [1.0, 1.0]) == 0.0  # zero vector, no division error


@pytest.mark.skipif(not _ollama_reachable(), reason="no local Ollama instance available")
@pytest.mark.asyncio
async def test_embed_bge_m3_returns_a_real_1024_dim_vector():
    embedding = await embed_bge_m3("URGENT: your account will be suspended")
    assert embedding is not None
    assert len(embedding) == 1024  # bge-m3's real output dimension


@pytest.mark.skipif(not _ollama_reachable(), reason="no local Ollama instance available")
@pytest.mark.asyncio
async def test_embed_bge_m3_khmer_text_is_not_blind():
    # The whole point of this feature: unlike the hashed scheme (0.000
    # similarity on every Khmer case, confirmed in an earlier session),
    # bge-m3 must actually produce a real, non-degenerate embedding for
    # Khmer script.
    khmer_scam_text = "បន្ទាន់ សូមផ្ញើលុយឥឡូវនេះ គណនីរបស់អ្នកនឹងត្រូវផ្អាក"
    embedding = await embed_bge_m3(khmer_scam_text)
    assert embedding is not None
    assert any(abs(x) > 0.001 for x in embedding)  # genuinely non-zero, not a degenerate/empty vector


@pytest.mark.skipif(not _ollama_reachable(), reason="no local Ollama instance available")
@pytest.mark.asyncio
async def test_embed_bge_m3_unreachable_returns_none(monkeypatch):
    import bot.detectors.text.online.bge_m3_embed as mod
    monkeypatch.setattr(mod, "OLLAMA_URL", "http://localhost:1")  # nothing listens here
    result = await embed_bge_m3("test")
    assert result is None
