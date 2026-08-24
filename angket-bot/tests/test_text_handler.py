from bot.handlers.text_handler import format_analysis_response


def _result(risk_percentage, verdict="Scam"):
    return {
        "verdict": verdict,
        "risk_percentage": risk_percentage,
        "key_reasons": ["Uses an unrealistic offer <now>"],
        "recommendations": ["Do not click the link"],
    }


def test_format_analysis_response_uses_high_risk_style():
    response = format_analysis_response(
        _result(85), {"suspicious": False, "matches": []}
    )

    assert "⚠️ <b>VERDICT: LIKELY A SCAM</b>" in response
    assert "This message shows strong signs of being unsafe." in response
    assert "🔴 <b>85%  HIGH RISK</b>" in response
    assert "🔍 <b>KEY REASONS</b>" in response
    assert "💡 <b>WHAT YOU SHOULD DO</b>" in response
    assert "• Uses an unrealistic offer &lt;now&gt;" in response
    assert "ⓘ Angket Bot may occasionally make mistakes." in response
    assert "────────────────────" in response
    assert "1. Verdict" not in response


def test_format_analysis_response_uses_medium_and_low_thresholds():
    medium = format_analysis_response(
        _result(31, verdict="Uncertain"), {"suspicious": False, "matches": []}
    )
    low = format_analysis_response(
        _result(30, verdict="Not a Scam"), {"suspicious": False, "matches": []}
    )

    assert "🟠 <b>31%  MEDIUM RISK</b>" in medium
    assert "⚠️ <b>VERDICT: SUSPICIOUS</b>" in medium
    assert "This message has warning signs. Verify it before taking action." in medium
    assert "🟢 <b>30%  LOW RISK</b>" in low
    assert "✅ <b>VERDICT: SAFE / LEGITIMATE</b>" in low
    assert "No strong scam indicators were detected in this message." in low


def test_format_analysis_response_includes_keyword_match_only_when_present():
    response = format_analysis_response(
        _result(61), {"suspicious": True, "matches": ["claim <reward>"]}
    )

    assert "⚠️ <b>KEYWORD MATCH:</b> <code>claim &lt;reward&gt;</code>" in response