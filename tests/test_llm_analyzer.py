import asyncio
from unittest.mock import AsyncMock, patch

from bot.detectors.text.online import llm as llm_analyzer


def test_analyze_text_with_llm_without_api_key():
    # 2026-09-11 spec: no Gemini key configured still runs the offline
    # fallback (keyword + scam-pattern similarity) instead of a blank
    # "Uncertain, N/A risk" - a neutral message with no red flags should
    # come back "Not a Scam", not "we have no idea".
    with patch.object(llm_analyzer, "_client", None):
        result = asyncio.run(llm_analyzer.analyze_text_with_llm("hello"))

    assert result["verdict"] == "Not a Scam"
    assert result["error"] == "missing_api_key"


def test_analyze_text_with_llm_without_api_key_still_flags_a_real_keyword_match():
    with patch.object(llm_analyzer, "_client", None):
        result = asyncio.run(
            llm_analyzer.analyze_text_with_llm("congrats! claim reward now before it expires")
        )

    assert result["verdict"] in ("Scam", "Uncertain")
    assert result["key_reasons"]  # real evidence, not an empty list
    assert isinstance(result["key_reasons"][0], str)  # flattened, not context_engine's {text, source} shape


def test_analyze_text_with_llm_returns_parsed_verdict():
    fake_response = type(
        "FakeResponse",
        (),
        {
            "text": (
                '{"verdict": "Scam", "risk_level": "High", "risk_percentage": 87, '
                '"key_reasons": ["Asks for money"], "recommendations": ["Do not reply"]}'
            )
        },
    )()
    fake_client = type(
        "FakeClient",
        (),
        {"aio": type("Aio", (), {"models": type("Models", (), {
            "generate_content": AsyncMock(return_value=fake_response),
        })()})()},
    )()

    with patch.object(llm_analyzer, "_client", fake_client):
        result = asyncio.run(llm_analyzer.analyze_text_with_llm("free bitcoin!"))

    assert result == {
        "verdict": "Scam",
        "risk_level": "High",
        "risk_percentage": 87,
        "key_reasons": ["Asks for money"],
        "recommendations": ["Do not reply"],
    }



def test_analyze_text_with_llm_falls_back_without_a_real_call_once_circuit_is_open():
    # 2026-09-16, mentor/teammate spec - same breaker as
    # gemini_retry.py's own tests, this just proves the group-chat
    # caller (llm.py) wires into it the same way context_engine.py does:
    # falls back cleanly, makes no real call, doesn't re-record a
    # health_alerts failure for a call that never happened.
    import time

    from bot.detectors.text.online import gemini_retry

    fake_client = type(
        "FakeClient", (), {"aio": type("Aio", (), {"models": type("Models", (), {
            "generate_content": AsyncMock(return_value="should never be reached"),
        })()})()},
    )()

    with patch.object(llm_analyzer, "_client", fake_client), \
         patch.object(gemini_retry, "_consecutive_failures", gemini_retry.CIRCUIT_FAILURE_THRESHOLD), \
         patch.object(gemini_retry, "_circuit_open_until", time.time() + 30), \
         patch.object(llm_analyzer.health_alerts, "record_failure") as mock_record:
        result = asyncio.run(llm_analyzer.analyze_text_with_llm("hello"))

    fake_client.aio.models.generate_content.assert_not_called()
    mock_record.assert_not_called()
    assert "circuit open" in result["error"].lower()
