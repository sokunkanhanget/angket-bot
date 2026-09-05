import asyncio
from unittest.mock import AsyncMock, patch

from bot.detectors.text.online import llm as llm_analyzer


def test_analyze_text_with_llm_without_api_key():
    with patch.object(llm_analyzer, "_client", None):
        result = asyncio.run(llm_analyzer.analyze_text_with_llm("hello"))

    assert result["verdict"] == "Uncertain"
    assert result["error"] == "missing_api_key"


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


