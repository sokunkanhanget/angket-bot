"""
tests/test_context_engine.py
==============================
Offline tests for the unified reasoning fallback (no GEMINI_API_KEY
configured / call failure) - the live Gemini path is exercised by the
run-angket-bot skill's driver, same as llm_analyzer.py's live path.
"""

import asyncio

from bot.context_engine import _grounded_fallback, analyze_unified


def test_grounded_fallback_includes_keyword_and_link_evidence():
    keyword_result = {"suspicious": True, "matches": ["urgent"]}
    link_verdicts = [
        {"host": "free-prize-winner.tk", "level": "dangerous", "score": 80,
         "reasons": ["Domain ends in .tk, a free TLD heavily used for scams."]},
        {"host": "example.com", "level": "safe", "score": 0, "reasons": []},
    ]

    result = _grounded_fallback("LLM analysis is not configured.", keyword_result, link_verdicts)

    assert result["verdict"] == "Uncertain"
    assert result["risk_percentage"] == 80
    sources = {r["source"] for r in result["key_reasons"]}
    assert "keyword_match" in sources
    assert "link_evidence" in sources
    # the safe link must not add a reason
    assert not any("example.com" in r["text"] for r in result["key_reasons"])


def test_grounded_fallback_risk_percentage_none_without_links():
    result = _grounded_fallback("x", {"suspicious": False, "matches": []}, [])
    assert result["risk_percentage"] is None
    assert result["verdict"] == "Uncertain"


def test_analyze_unified_degrades_without_api_key(monkeypatch):
    # No API key configured -> must return the grounded fallback, never
    # raise and never return a bare "not configured" verdict with no
    # local evidence attached.
    import bot.context_engine as ce
    monkeypatch.setattr(ce, "_client", None)

    keyword_result = {"suspicious": True, "matches": ["free bitcoin"]}
    link_verdicts = []

    result = asyncio.run(analyze_unified("free bitcoin now!!!", keyword_result, link_verdicts))

    assert result["verdict"] == "Uncertain"
    assert any(r["source"] == "keyword_match" for r in result["key_reasons"])
