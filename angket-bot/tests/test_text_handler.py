from unittest.mock import AsyncMock, patch

import pytest

from bot.i18n import key_for_label, label
from bot.handlers.text_handler import (
    MAIN_MENU_KEYBOARD,
    format_analysis_response,
    get_language_keyboard,
    get_user_lang,
    handle_text,
)


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


def test_key_for_label_and_language_keyboard_are_available():
    assert key_for_label("🌐 Switch Language") == "switch_language"
    assert key_for_label("🌐 ផ្លាស់ប្តូរភាសា") == "switch_language"
    assert key_for_label("English") == "lang_en"
    assert key_for_label("ខ្មែរ") == "lang_km"
    keyboard = get_language_keyboard("km")
    assert keyboard.keyboard[0][0].text == label("km", "lang_en")
    assert keyboard.keyboard[0][1].text == label("km", "lang_km")
    assert keyboard.keyboard[1][0].text == label("km", "back")


def test_get_user_lang_defaults_and_persists_context():
    context = type("Ctx", (), {"user_data": {}})()
    assert get_user_lang(context) == "en"

    context.user_data["lang"] = "km"
    assert get_user_lang(context) == "km"


@pytest.mark.asyncio
async def test_handle_text_shows_language_keyboard_on_switch_language():
    update = AsyncMock()
    update.message.text = "🌐 Switch Language"
    update.message.reply_text = AsyncMock()
    context = type("Ctx", (), {"user_data": {}})()

    await handle_text(update, context)

    update.message.reply_text.assert_awaited_once()
    call_args = update.message.reply_text.call_args[0]
    assert "Switch Language" in call_args[0]
    _, kwargs = update.message.reply_text.await_args
    assert kwargs["reply_markup"] == get_language_keyboard("en")
    assert kwargs["reply_markup"].keyboard[0][0].text == "English"


@pytest.mark.asyncio
async def test_handle_text_shows_how_to_use_guidance():
    update = AsyncMock()
    update.message.text = "📖 How to Use"
    update.message.reply_text = AsyncMock()
    context = type("Ctx", (), {"user_data": {}})()

    await handle_text(update, context)

    response = update.message.reply_text.call_args[0][0]
    assert "How to Use Angket Bot" in response
    assert "1. Send the content you want to check" in response
    assert "2. Let Angket analyze it" in response
    assert "3. Get your result" in response
    assert "🟢 <b>Low Risk:</b>" in response
    assert "🟡 <b>Medium Risk:</b>" in response
    assert "🔴 <b>High Risk:</b>" in response


@pytest.mark.asyncio
async def test_handle_text_analyzes_regular_messages():
    update = AsyncMock()
    update.message.text = "This is a test message"
    update.message.reply_text = AsyncMock()
    context = type("Ctx", (), {"user_data": {}})()

    with patch("bot.handlers.text_handler.analyze_text", return_value={"suspicious": False, "matches": []}), patch(
        "bot.handlers.text_handler.analyze_text_with_llm",
        AsyncMock(return_value={
            "verdict": "Scam",
            "risk_percentage": 90,
            "key_reasons": ["Urgent request"],
            "recommendations": ["Be careful"],
        }),
    ):
        await handle_text(update, context)

    update.message.reply_text.assert_awaited_once()
    call_args = update.message.reply_text.call_args[0]
    assert "VERDICT" in call_args[0]
    _, kwargs = update.message.reply_text.await_args
    assert kwargs["reply_markup"] == MAIN_MENU_KEYBOARD
    assert kwargs["reply_markup"].keyboard[0][0].text == "🌐 Switch Language"