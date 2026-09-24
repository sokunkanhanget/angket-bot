"""
tests/test_scam_patterns_bge_m3.py
=====================================
Tests for nearest_scam_pattern_live() - the real 3-tier (bge-m3 ->
Gemini embedding -> hashed) entry point context_engine.py's live path
now calls. Returns (hits, source) where source is "bge_m3", "gemini", or
"hashed" - which one matters because each tier runs on a different
similarity SCALE (see BGE_M3_PATTERN_THRESHOLD/GEMINI_EMBED_PATTERN_THRESHOLD
in bot/config/config.py, the former calibrated from these very tests
catching a real threshold-reuse bug during development).

Split from test_scam_patterns.py (which covers the plain, always-on
hashed nearest_scam_pattern()) since these specifically exercise the
USE_BGE_M3_EMBEDDINGS flag and, for the "really works" cases, a real
Modal-hosted bge-m3 deployment - gated with the same skip pattern as
test_bge_m3_embed.py so this suite still runs clean with no network on
a machine without that reachable. Neutralizes the Gemini fallback tier
(gemini_embed._client) in the bge-m3-fails tests specifically, so those
test bge-m3's OWN fallback-to-hashed behavior in isolation, unaffected
by the newer intermediate tier - see test_scam_patterns_gemini.py for
the 3-tier chain itself.
"""

import asyncio

import httpx
import pytest

from bot.detectors.text.offline import scam_patterns
from bot.detectors.text.online import gemini_embed
from bot.config.config import BGE_M3_PATTERN_THRESHOLD, OLLAMA_URL


def _ollama_reachable() -> bool:
    try:
        httpx.get(f"{OLLAMA_URL}/api/version", timeout=2)
        return True
    except Exception:
        return False


@pytest.fixture(autouse=True)
def _reset_bge_m3_index():
    """The module-level index caches must not leak between tests - an
    earlier test building one (or leaving it None after a simulated
    failure) would silently change a later test's code path."""
    scam_patterns._bge_m3_index = None
    scam_patterns._gemini_index = None
    yield
    scam_patterns._bge_m3_index = None
    scam_patterns._gemini_index = None


@pytest.mark.asyncio
async def test_flag_off_uses_the_plain_hashed_scheme_directly(monkeypatch):
    monkeypatch.setattr("bot.config.config.USE_BGE_M3_EMBEDDINGS", False)
    monkeypatch.setattr(gemini_embed, "_client", None)  # isolate: bge-m3 off, Gemini tier off too
    text = "Mom, I lost my phone, this is my friend's number. I'm in trouble and need money right now, please don't call, just trust me."

    live_hits, source = await scam_patterns.nearest_scam_pattern_live(text, k=1)
    direct_hits = scam_patterns.nearest_scam_pattern(text, k=1)

    assert live_hits == direct_hits
    assert source == "hashed"
    assert scam_patterns._bge_m3_index is None  # never even attempted to build it


@pytest.mark.asyncio
async def test_flag_on_but_ollama_unreachable_falls_back_to_hashed_when_gemini_also_off(monkeypatch):
    monkeypatch.setattr("bot.config.config.USE_BGE_M3_EMBEDDINGS", True)
    monkeypatch.setattr("bot.detectors.text.online.bge_m3_embed.OLLAMA_URL", "http://localhost:1")
    monkeypatch.setattr(gemini_embed, "_client", None)  # isolate: no Gemini tier available either
    text = "free bitcoin now, click nowhere"

    # Must not raise, and must return the same real answer the hashed
    # scheme alone would give - a broken bge-m3 path must never mean
    # "no answer at all". source must honestly say "hashed" - the
    # caller (context_engine.py) needs this to pick the right threshold.
    live_hits, source = await scam_patterns.nearest_scam_pattern_live(text, k=1)
    direct_hits = scam_patterns.nearest_scam_pattern(text, k=1)
    assert live_hits == direct_hits
    assert source == "hashed"


@pytest.mark.skipif(not _ollama_reachable(), reason="no local Ollama instance available")
@pytest.mark.asyncio
async def test_flag_on_and_ollama_reachable_actually_uses_bge_m3(monkeypatch):
    monkeypatch.setattr("bot.config.config.USE_BGE_M3_EMBEDDINGS", True)

    # A Khmer paraphrase of the family_emergency script - the hashed
    # scheme is blind to Khmer (confirmed elsewhere: ~0.14 similarity to
    # its own English original), so if THIS call correctly matches it to
    # family_emergency with real confidence, bge-m3 - not the hashed
    # fallback - is what actually ran.
    khmer_text = "ម៉ាក់ខ្ញុំបានបាត់ទូរស័ព្ទ នេះជាលេខរបស់មិត្តខ្ញុំ ខ្ញុំកំពុងមានបញ្ហា ត្រូវការលុយឥឡូវនេះ សូមកុំទូរស័ព្ទមក"

    hits, source = await scam_patterns.nearest_scam_pattern_live(khmer_text, k=1)

    assert source == "bge_m3"
    assert hits
    similarity, kind, key, category = hits[0]
    assert category == "family_emergency"
    assert similarity >= BGE_M3_PATTERN_THRESHOLD  # real bge-m3 confidence, on bge-m3's own scale
    assert scam_patterns._bge_m3_index is not None  # the real index actually got built


@pytest.mark.skipif(not _ollama_reachable(), reason="no local Ollama instance available")
@pytest.mark.asyncio
async def test_bge_m3_correctly_categorizes_khmer_examples_across_scam_types(monkeypatch):
    monkeypatch.setattr("bot.config.config.USE_BGE_M3_EMBEDDINGS", True)
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
        hits, source = await scam_patterns.nearest_scam_pattern_live(text, k=1)
        assert source == "bge_m3"
        assert hits, f"no match at all for: {text!r}"
        similarity, _kind, _key, category = hits[0]
        assert category == expected_category, (
            f"expected {expected_category!r} for {text!r}, got {category!r} (similarity {similarity:.3f})"
        )
        assert similarity >= BGE_M3_PATTERN_THRESHOLD, f"low confidence ({similarity:.3f}) for {text!r}"


@pytest.mark.skipif(not _ollama_reachable(), reason="no local Ollama instance available")
@pytest.mark.asyncio
async def test_bge_m3_scores_genuinely_benign_khmer_text_below_its_own_threshold(monkeypatch):
    monkeypatch.setattr("bot.config.config.USE_BGE_M3_EMBEDDINGS", True)
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
        hits, source = await scam_patterns.nearest_scam_pattern_live(text, k=1)
        assert source == "bge_m3"
        assert hits
        similarity = hits[0][0]
        assert similarity < BGE_M3_PATTERN_THRESHOLD, f"benign text scored too high ({similarity:.3f}): {text!r}"


@pytest.mark.skipif(not _ollama_reachable(), reason="no local Ollama instance available")
@pytest.mark.asyncio
async def test_bge_m3_index_is_built_once_and_reused(monkeypatch):
    monkeypatch.setattr("bot.config.config.USE_BGE_M3_EMBEDDINGS", True)

    await scam_patterns.nearest_scam_pattern_live("test message one", k=1)
    index_after_first_call = scam_patterns._bge_m3_index
    assert index_after_first_call is not None

    await scam_patterns.nearest_scam_pattern_live("test message two", k=1)
    # Same object, not rebuilt - proves the lazy-build-once behavior,
    # not just "it happens to still work".
    assert scam_patterns._bge_m3_index is index_after_first_call


# --- failed-build negative cache (2026-09-24 networking review) -------
#
# Fully mocked, no real Modal/Ollama call - deliberately NOT gated
# behind _ollama_reachable() like the tests above, since the whole
# point is the behavior when that endpoint is exactly what's NOT
# reachable.


@pytest.mark.asyncio
async def test_a_failed_index_build_is_not_retried_on_every_single_message(monkeypatch):
    # Real defect this locks in (found by a networking audit): a failed
    # build cached nothing, so the next message re-entered and re-ran a
    # full 30-call concurrent embedding burst, each call bounded at
    # bge_m3_embed.TIMEOUT_SECONDS (30s) - and serialized behind the
    # build lock, so a burst of users queued behind each other and the
    # last one could wait minutes. Only the SUCCESS path was cached.
    monkeypatch.setattr(scam_patterns, "_bge_m3_index", None)
    monkeypatch.setattr(scam_patterns, "_bge_m3_index_retry_after", 0.0)

    call_count = 0

    async def _unreachable_modal(text):
        nonlocal call_count
        call_count += 1
        return None

    monkeypatch.setattr(
        "bot.detectors.text.online.bge_m3_embed.embed_bge_m3", _unreachable_modal
    )

    seed_row_count = len(scam_patterns._seed_rows())

    results = await asyncio.gather(
        *(scam_patterns._ensure_bge_m3_index() for _ in range(5))
    )

    assert all(result is False for result in results)
    # Exactly ONE build attempt total across 5 concurrent callers, not
    # one per caller. The pre-fix number here was seed_row_count * 5.
    assert call_count == seed_row_count


@pytest.mark.asyncio
async def test_the_index_build_cooldown_expires_so_a_recovered_modal_is_picked_up(monkeypatch):
    # The other half: a cooled-off failure must not become permanent -
    # a Modal COLD START is a real, common transient here, not an
    # outage, so the bot has to retry once the window passes.
    monkeypatch.setattr(scam_patterns, "_bge_m3_index", None)
    monkeypatch.setattr(scam_patterns, "_bge_m3_index_retry_after", 0.0)

    attempts = 0

    async def _fails_then_recovers(text):
        nonlocal attempts
        attempts += 1
        return None if attempts <= len(scam_patterns._seed_rows()) else [0.1, 0.2, 0.3]

    monkeypatch.setattr(
        "bot.detectors.text.online.bge_m3_embed.embed_bge_m3", _fails_then_recovers
    )

    assert await scam_patterns._ensure_bge_m3_index() is False
    # Still inside the cooldown - refused without attempting anything.
    calls_after_failure = attempts
    assert await scam_patterns._ensure_bge_m3_index() is False
    assert attempts == calls_after_failure

    # Simulate the cooldown having elapsed.
    monkeypatch.setattr(scam_patterns, "_bge_m3_index_retry_after", 0.0)
    assert await scam_patterns._ensure_bge_m3_index() is True
    assert scam_patterns._bge_m3_index is not None
