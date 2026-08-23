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

    assert "⚠️ <b>Verdict: Likely a SCAM</b>" in response
    assert "🔴 <b>85% High Risk</b>" in response
    assert "🔍 <b>Key Reasons</b>" in response
    assert "💡 <b>What You Can Do</b>" in response
    assert "• Uses an unrealistic offer &lt;now&gt;" in response
    assert "ⓘ Our bot can make mistakes sometimes." in response
    assert "1. Verdict" not in response


def test_format_analysis_response_uses_medium_and_low_thresholds():
    medium = format_analysis_response(
        _result(31, verdict="Uncertain"), {"suspicious": False, "matches": []}
    )
    low = format_analysis_response(
        _result(30, verdict="Not a Scam"), {"suspicious": False, "matches": []}
    )

    assert "🟠 <b>31% Medium Risk</b>" in medium
    assert "⚠️ <b>Verdict: SUSPICIOUS</b>" in medium
    assert "🟢 <b>30% Low Risk</b>" in low
    assert "✅ <b>Verdict: SAFE / LEGITIMATE</b>" in low


def test_format_analysis_response_includes_keyword_match_only_when_present():
    response = format_analysis_response(
        _result(61), {"suspicious": True, "matches": ["claim <reward>"]}
    )

    assert "⚠️ <b>Keyword match:</b> <code>claim &lt;reward&gt;</code>" in response