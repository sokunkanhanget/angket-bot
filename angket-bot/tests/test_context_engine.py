"""
tests/test_context_engine.py
==============================
Offline tests for the unified reasoning fallback (no GEMINI_API_KEY
configured / call failure) - the live Gemini path is exercised by the
run-angket-bot skill's driver, same as llm_analyzer.py's live path.

_grounded_fallback and vectors.seed() are both async now (the
scam-pattern lookup goes through the Postgres-backed vector store) -
every test here uses the shared `fake_vector_store` fixture from
tests/conftest.py so no test hits the real network.
"""

import pytest

from bot.context_engine import _grounded_fallback, analyze_unified


@pytest.mark.asyncio
async def test_grounded_fallback_includes_keyword_and_link_evidence(fake_vector_store):
    keyword_result = {"suspicious": True, "matches": ["urgent"]}
    link_verdicts = [
        {"host": "free-prize-winner.tk", "level": "dangerous", "score": 80,
         "reasons": ["Domain ends in .tk, a free TLD heavily used for scams."]},
        {"host": "example.com", "level": "safe", "score": 0, "reasons": []},
    ]

    result = await _grounded_fallback("LLM analysis is not configured.", "", keyword_result, link_verdicts)

    assert result["verdict"] == "Uncertain"
    assert result["risk_percentage"] == 80
    sources = {r["source"] for r in result["key_reasons"]}
    assert "keyword_match" in sources
    assert "link_evidence" in sources
    # the safe link must not add a reason
    assert not any("example.com" in r["text"] for r in result["key_reasons"])


@pytest.mark.asyncio
async def test_grounded_fallback_returns_not_a_scam_when_nothing_found(fake_vector_store):
    # No keyword match, no link, no file, no scam-pattern hit - the
    # fallback must confidently say "Not a Scam" rather than a vague
    # "Uncertain" that would spam a business owner on every mundane
    # message during a Gemini outage.
    result = await _grounded_fallback("x", "hey, are we still on for lunch tomorrow?",
                                       {"suspicious": False, "matches": []}, [])
    assert result["verdict"] == "Not a Scam"
    assert result["risk_percentage"] is None


@pytest.mark.asyncio
async def test_grounded_fallback_flags_malicious_file(fake_vector_store):
    file_verdict = {"found": True, "malicious": 5, "suspicious": 0, "total": 70}
    result = await _grounded_fallback("x", "", {"suspicious": False, "matches": []}, [], file_verdict)

    assert result["verdict"] == "Scam"
    assert result["risk_percentage"] == 100
    assert any(r["source"] == "file_evidence" for r in result["key_reasons"])


@pytest.mark.asyncio
async def test_grounded_fallback_ignores_clean_file(fake_vector_store):
    file_verdict = {"found": True, "malicious": 0, "suspicious": 0, "total": 70}
    result = await _grounded_fallback("x", "", {"suspicious": False, "matches": []}, [], file_verdict)

    assert result["verdict"] == "Not a Scam"
    assert not any(r["source"] == "file_evidence" for r in result["key_reasons"])
    # Regression (found by /code-review's removed-behavior audit): a
    # scanned-but-clean file must show a coherent "0% Low Risk", not
    # "N/A Unknown Risk" - the equivalent safe-link-only case already
    # produces risk_percentage=0, so this must match for consistency.
    assert result["risk_percentage"] == 0


@pytest.mark.asyncio
async def test_grounded_fallback_flags_near_exact_scam_script(seeded_vectors):
    # Regression/calibration: a near-verbatim repeat of a seeded scam
    # script must be caught even with zero keyword matches and no link -
    # this is exactly the "Hi Mom" case that motivated context_engine.py
    # in the first place, now also covered in DEGRADED (no-LLM) mode.
    text = ("Mom, this is urgent, I lost my phone and I'm texting from a friend's. "
            "I need you to send $800 right now to help me, don't call, just trust me "
            "on this one time.")

    result = await _grounded_fallback("x", text, {"suspicious": False, "matches": []}, [])

    assert result["verdict"] == "Uncertain"
    assert any(
        r["source"] == "message_text" and "scam script" in r["text"]
        for r in result["key_reasons"]
    )
    # Regression (found by /code-review's removed-behavior audit): a
    # confident offline pattern match must show up in the risk NUMBER
    # too, not just the reasons list, or the owner-DM shows "Uncertain"
    # right next to "N/A Unknown Risk" - undercutting the exact signal
    # this fallback exists to surface.
    assert result["risk_percentage"] is not None
    assert result["risk_percentage"] >= 50  # matches SCAM_PATTERN_THRESHOLD


@pytest.mark.asyncio
async def test_grounded_fallback_pattern_match_not_diluted_by_a_safe_link(seeded_vectors):
    # A confident scam-script match plus an unrelated SAFE link must not
    # have its risk number dragged down to the link's low score.
    text = ("Mom, this is urgent, I lost my phone and I'm texting from a friend's. "
            "I need you to send $800 right now to help me, don't call, just trust me "
            "on this one time.")
    link_verdicts = [{"host": "example.com", "level": "safe", "score": 5, "reasons": []}]

    result = await _grounded_fallback("x", text, {"suspicious": False, "matches": []}, link_verdicts)

    assert result["risk_percentage"] >= 50


@pytest.mark.asyncio
async def test_grounded_fallback_does_not_flag_paraphrased_or_benign_text(seeded_vectors):
    # Calibrated live (calibrate_scam_patterns.py): paraphrased scam
    # variants and genuinely benign messages both score well below
    # SCAM_PATTERN_THRESHOLD with this embedding scheme - the threshold
    # is deliberately conservative (only near-exact script repeats),
    # so both must come back "Not a Scam" here, not a false positive.
    for text in (
        "hey, are we still on for lunch tomorrow?",
        "what time do you open tomorrow? also do you have parking nearby?",
        "join my exclusive trading group, I turned a small amount into a lot in a month, message me now",
    ):
        result = await _grounded_fallback("x", text, {"suspicious": False, "matches": []}, [])
        assert result["verdict"] == "Not a Scam", f"false positive on: {text!r}"


@pytest.mark.asyncio
async def test_analyze_unified_degrades_without_api_key(fake_vector_store, monkeypatch):
    # No API key configured -> must return the grounded fallback, never
    # raise and never return a bare "not configured" verdict with no
    # local evidence attached.
    import bot.context_engine as ce
    monkeypatch.setattr(ce, "_client", None)

    keyword_result = {"suspicious": True, "matches": ["free bitcoin"]}
    link_verdicts = []

    result = await analyze_unified("free bitcoin now!!!", keyword_result, link_verdicts)

    assert result["verdict"] == "Uncertain"
    assert any(r["source"] == "keyword_match" for r in result["key_reasons"])


@pytest.mark.asyncio
async def test_grounded_fallback_survives_a_broken_vector_db(monkeypatch):
    # Regression: reported live as "private chat gives no reply at all".
    # _grounded_fallback is the LAST-RESORT path (Gemini already failed),
    # so if its own scam-pattern DB lookup also raises (e.g. Supabase
    # unreachable) with no protection, the exception has nowhere left to
    # go - it propagates out of handle_text uncaught and the user gets
    # zero reply instead of a degraded one.
    import bot.context_engine as ce

    def _boom(*args, **kwargs):
        raise RuntimeError("connection to Supabase failed")

    monkeypatch.setattr(ce, "vector_nearest", _boom)

    result = await _grounded_fallback(
        "LLM analysis failed, please try again later.",
        "hey, are we still on for lunch tomorrow?",
        {"suspicious": False, "matches": []},
        [],
    )

    assert result["verdict"] == "Not a Scam"
