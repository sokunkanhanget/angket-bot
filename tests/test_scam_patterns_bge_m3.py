"""
tests/test_scam_patterns_bge_m3.py
=====================================
Tests for nearest_scam_pattern_live() - the real bge-m3-preferring,
safe-fallback entry point context_engine.py's live path now calls.
Returns (hits, used_bge_m3) - the second value matters because bge-m3
runs on a different similarity SCALE than the hashed scheme (see
BGE_M3_PATTERN_THRESHOLD in bot/config.py, calibrated from these very
tests catching a real threshold-reuse bug during development).

Split from test_scam_patterns.py (which covers the plain, always-on
hashed nearest_scam_pattern()) since these specifically exercise the
USE_BGE_M3_EMBEDDINGS flag and, for the "really works" cases, a real
local Ollama - gated with the same skip pattern as test_bge_m3_embed.py
so this suite still runs clean with no network on a machine without
Ollama installed.
"""

import httpx
import pytest

from bot.detectors.text.offline import scam_patterns
from bot.config import BGE_M3_PATTERN_THRESHOLD, OLLAMA_URL


def _ollama_reachable() -> bool:
    try:
        httpx.get(f"{OLLAMA_URL}/api/version", timeout=2)
        return True
    except Exception:
        return False


@pytest.fixture(autouse=True)
def _reset_bge_m3_index():
    """The module-level index cache must not leak between tests - an
    earlier test building it (or leaving it None after a simulated
    failure) would silently change a later test's code path."""
    scam_patterns._bge_m3_index = None
    yield
    scam_patterns._bge_m3_index = None


@pytest.mark.asyncio
async def test_flag_off_uses_the_plain_hashed_scheme_directly(monkeypatch):
    monkeypatch.setattr("bot.config.USE_BGE_M3_EMBEDDINGS", False)
    text = "Mom, I lost my phone, this is my friend's number. I'm in trouble and need money right now, please don't call, just trust me."

    live_hits, used_bge_m3 = await scam_patterns.nearest_scam_pattern_live(text, k=1)
    direct_hits = scam_patterns.nearest_scam_pattern(text, k=1)

    assert live_hits == direct_hits
    assert used_bge_m3 is False
    assert scam_patterns._bge_m3_index is None  # never even attempted to build it


@pytest.mark.asyncio
async def test_flag_on_but_ollama_unreachable_falls_back_safely(monkeypatch):
    monkeypatch.setattr("bot.config.USE_BGE_M3_EMBEDDINGS", True)
    monkeypatch.setattr("bot.detectors.text.online.bge_m3_embed.OLLAMA_URL", "http://localhost:1")
    text = "free bitcoin now, click nowhere"

    # Must not raise, and must return the same real answer the hashed
    # scheme alone would give - a broken bge-m3 path must never mean
    # "no answer at all". used_bge_m3 must honestly say False - the
    # caller (context_engine.py) needs this to pick the right threshold.
    live_hits, used_bge_m3 = await scam_patterns.nearest_scam_pattern_live(text, k=1)
    direct_hits = scam_patterns.nearest_scam_pattern(text, k=1)
    assert live_hits == direct_hits
    assert used_bge_m3 is False


@pytest.mark.skipif(not _ollama_reachable(), reason="no local Ollama instance available")
@pytest.mark.asyncio
async def test_flag_on_and_ollama_reachable_actually_uses_bge_m3(monkeypatch):
    monkeypatch.setattr("bot.config.USE_BGE_M3_EMBEDDINGS", True)

    # A Khmer paraphrase of the family_emergency script - the hashed
    # scheme is blind to Khmer (confirmed elsewhere: ~0.14 similarity to
    # its own English original), so if THIS call correctly matches it to
    # family_emergency with real confidence, bge-m3 - not the hashed
    # fallback - is what actually ran.
    khmer_text = "ម៉ាក់ខ្ញុំបានបាត់ទូរស័ព្ទ នេះជាលេខរបស់មិត្តខ្ញុំ ខ្ញុំកំពុងមានបញ្ហា ត្រូវការលុយឥឡូវនេះ សូមកុំទូរស័ព្ទមក"

    hits, used_bge_m3 = await scam_patterns.nearest_scam_pattern_live(khmer_text, k=1)

    assert used_bge_m3 is True
    assert hits
    similarity, kind, key, category = hits[0]
    assert category == "family_emergency"
    assert similarity >= BGE_M3_PATTERN_THRESHOLD  # real bge-m3 confidence, on bge-m3's own scale
    assert scam_patterns._bge_m3_index is not None  # the real index actually got built


@pytest.mark.skipif(not _ollama_reachable(), reason="no local Ollama instance available")
@pytest.mark.asyncio
async def test_bge_m3_correctly_categorizes_khmer_examples_across_scam_types(monkeypatch):
    monkeypatch.setattr("bot.config.USE_BGE_M3_EMBEDDINGS", True)
    # Expanded validation corpus - real-shaped Khmer paraphrases (not
    # translations of the exact seed examples) across several different
    # scam categories, not just family_emergency. Each must both match
    # its OWN category as the top hit AND clear the real, calibrated
    # bge-m3 confidence bar - matching the spirit of the earlier
    # 54-case sandbox validation, at a smaller scale for a unit test.
    cases = [
        # (Khmer text, expected top category)
        ("អ្នកឈ្នះរង្វាន់ជាទឹកប្រាក់ធំមួយ! ដើម្បីទទួលរង្វាន់សូមផ្ញើព័ត៌មានធនាគាររបស់អ្នកមកឥឡូវនេះ",
         "lottery_prize"),
        ("គណនីរបស់អ្នកនឹងត្រូវផ្អាកក្នុងរយៈពេល ២៤ ម៉ោង លុះត្រាតែអ្នកផ្ទៀងផ្ទាត់ព័ត៌មានឥឡូវនេះ",
         "account_verification"),
        ("នេះជាក្រសួងពន្ធដារ អ្នកជំពាក់ពន្ធមិនទាន់សង សូមបង់ភ្លាមៗ បើមិនដូច្នេះទេ នឹងចេញដីកាចាប់ខ្លួន",
         "authority_impersonation"),
    ]

    for text, expected_category in cases:
        hits, used_bge_m3 = await scam_patterns.nearest_scam_pattern_live(text, k=1)
        assert used_bge_m3 is True
        assert hits, f"no match at all for: {text!r}"
        similarity, _kind, _key, category = hits[0]
        assert category == expected_category, (
            f"expected {expected_category!r} for {text!r}, got {category!r} (similarity {similarity:.3f})"
        )
        assert similarity >= BGE_M3_PATTERN_THRESHOLD, f"low confidence ({similarity:.3f}) for {text!r}"


@pytest.mark.skipif(not _ollama_reachable(), reason="no local Ollama instance available")
@pytest.mark.asyncio
async def test_bge_m3_scores_genuinely_benign_khmer_text_below_its_own_threshold(monkeypatch):
    monkeypatch.setattr("bot.config.USE_BGE_M3_EMBEDDINGS", True)
    # The other half of real validation: proving it doesn't just match
    # EVERYTHING to some category. Compared against BGE_M3_PATTERN_THRESHOLD
    # (0.70), NOT a plain "should be near zero" assumption - bge-m3
    # genuinely runs hotter than the hashed scheme (confirmed live: real
    # benign Khmer text scored 0.593, well above what the hashed scheme's
    # own 0.5 threshold would tolerate, which is exactly the calibration
    # bug this test caught and led to introducing a separate threshold).
    benign_cases = [
        "សួស្តី តើអ្នកនៅឯណា? ខ្ញុំកំពុងរង់ចាំនៅភោជនីយដ្ឋាន",  # "hey where are you, waiting at the restaurant"
        "ថ្ងៃនេះអាកាសធាតុល្អណាស់ ចង់ទៅដើរលេង",  # "nice weather today, want to go out"
    ]
    for text in benign_cases:
        hits, used_bge_m3 = await scam_patterns.nearest_scam_pattern_live(text, k=1)
        assert used_bge_m3 is True
        assert hits
        similarity = hits[0][0]
        assert similarity < BGE_M3_PATTERN_THRESHOLD, f"benign text scored too high ({similarity:.3f}): {text!r}"


@pytest.mark.skipif(not _ollama_reachable(), reason="no local Ollama instance available")
@pytest.mark.asyncio
async def test_bge_m3_index_is_built_once_and_reused(monkeypatch):
    monkeypatch.setattr("bot.config.USE_BGE_M3_EMBEDDINGS", True)

    await scam_patterns.nearest_scam_pattern_live("test message one", k=1)
    index_after_first_call = scam_patterns._bge_m3_index
    assert index_after_first_call is not None

    await scam_patterns.nearest_scam_pattern_live("test message two", k=1)
    # Same object, not rebuilt - proves the lazy-build-once behavior,
    # not just "it happens to still work".
    assert scam_patterns._bge_m3_index is index_after_first_call
