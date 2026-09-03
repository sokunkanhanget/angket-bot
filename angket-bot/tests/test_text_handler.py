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
    update.effective_message = update.message
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
    update.effective_message = update.message
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
async def test_handle_text_analyzes_a_caption_when_text_is_absent():
    # Regression: a photo/document sent with a caption has .text = None
    # (the wording lives in .caption instead) - handle_text used to
    # bail out immediately in that case, so scam wording attached to a
    # file/photo was never scanned at all.
    update = AsyncMock()
    update.message.text = None
    update.message.caption = "URGENT: verify your account now or it will be suspended"
    update.message.reply_text = AsyncMock()
    update.effective_message = update.message

    with patch("bot.handlers.text_handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), patch(
        "bot.handlers.text_handler.analyze_text_with_llm",
        AsyncMock(return_value={
            "verdict": "Scam",
            "risk_percentage": 80,
            "key_reasons": ["Urgent request"],
            "recommendations": ["Be careful"],
        }),
    ):
        await handle_text(update, AsyncMock())

    update.message.reply_text.assert_awaited_once()
    assert "VERDICT" in update.message.reply_text.call_args[0][0]


def _private_update(text):
    update = AsyncMock()
    update.message.text = text
    update.message.caption = None
    update.message.document = None
    update.message.business_connection_id = None
    update.message.reply_text = AsyncMock()
    update.effective_message = update.message
    update.effective_chat.type = "private"
    return update


def _private_context():
    context = AsyncMock()
    context.bot_data = {"_vectors_seeded": True}  # skip real vector seeding
    return context


@pytest.mark.asyncio
async def test_handle_text_uses_unified_reasoning_in_plain_private_chat_no_link():
    # Plain private chat, no link: context-engineering path still fires
    # (unconditionally, per bot/context_engine.py), just with zero link
    # evidence - no "Checking..." status message needed since there's
    # nothing to network-trace.
    update = _private_update("free bitcoin now, click nowhere")
    context = _private_context()

    with patch("bot.handlers.text_handler.extract_text_link_entities", return_value=[]), patch(
        "bot.handlers.text_handler.check_message_full", AsyncMock(return_value=[])
    ), patch(
        "bot.handlers.text_handler.analyze_unified",
        AsyncMock(return_value={
            "verdict": "Scam",
            "risk_percentage": 90,
            "key_reasons": [{"text": "Promises free money", "source": "message_text"}],
            "recommendations": ["Ignore it"],
        }),
    ) as mock_unified:
        await handle_text(update, context)

    mock_unified.assert_awaited_once()
    update.message.reply_text.assert_awaited_once()
    reply = update.message.reply_text.call_args[0][0]
    assert "VERDICT: LIKELY A SCAM" in reply
    assert "Promises free money" in reply


@pytest.mark.asyncio
async def test_handle_text_checks_attached_file_in_plain_private_chat():
    # Regression: a private-chat document WITH a caption used to be
    # invisible to this unified check - handle_file (bot.py group 0)
    # scans the file on its own VT-only report, with no idea the caption
    # text is urgent/suspicious, and analyze_unified had no idea a file
    # was even attached. This only checks that the file verdict reaches
    # analyze_unified - handle_file's own separate reply/buttons for the
    # file itself are untouched by this fix.
    update = _private_update(None)
    update.message.caption = "please review this invoice urgently"
    update.message.document = AsyncMock()
    update.message.document.file_id = "file123"
    context = _private_context()

    with patch("bot.handlers.text_handler.extract_text_link_entities", return_value=[]), patch(
        "bot.handlers.text_handler.check_message_full", AsyncMock(return_value=[])
    ), patch(
        "bot.handlers.text_handler.download_and_hash", AsyncMock(return_value="deadbeef")
    ), patch(
        "bot.handlers.text_handler.scan_vt_hash",
        AsyncMock(return_value={"found": True, "malicious": 5, "suspicious": 0, "total": 70}),
    ), patch(
        "bot.handlers.text_handler.analyze_unified", AsyncMock(return_value={
            "verdict": "Scam",
            "risk_percentage": 100,
            "key_reasons": [{"text": "Attached file is malicious", "source": "file_evidence"}],
            "recommendations": ["Do not open the file"],
        }),
    ) as mock_unified:
        await handle_text(update, context)

    mock_unified.assert_awaited_once()
    text_arg, _keyword_result, _link_verdicts, file_verdict_arg, *_lang_arg = mock_unified.call_args[0]
    assert text_arg == "please review this invoice urgently"
    assert file_verdict_arg == {"found": True, "malicious": 5, "suspicious": 0, "total": 70}


@pytest.mark.asyncio
async def test_handle_text_shows_status_and_edits_it_when_a_link_is_present():
    # A link in a plain private-chat message must show the "Checking..."
    # status first (network trace can take a while), then EDIT that same
    # message into the unified verdict - not send a second new message.
    update = _private_update("official update, click http://free-prize-winner.tk/claim")
    context = _private_context()

    status_message = AsyncMock()
    update.message.reply_text = AsyncMock(return_value=status_message)

    with patch("bot.handlers.text_handler.extract_text_link_entities", return_value=[]), patch(
        "bot.handlers.text_handler.check_message_full",
        AsyncMock(return_value=[{"host": "free-prize-winner.tk", "level": "dangerous",
                                  "score": 80, "reasons": ["scam TLD"]}]),
    ), patch(
        "bot.handlers.text_handler.analyze_unified",
        AsyncMock(return_value={
            "verdict": "Scam",
            "risk_percentage": 95,
            "key_reasons": [{"text": "Link uses a scam TLD", "source": "link_evidence"}],
            "recommendations": ["Do not click"],
        }),
    ):
        await handle_text(update, context)

    update.message.reply_text.assert_awaited_once_with("🔍 Checking...", parse_mode="Markdown")
    status_message.edit_text.assert_awaited_once()
    edited_text = status_message.edit_text.call_args[0][0]
    assert "🔗" in edited_text  # link-sourced reason tagged
    assert "Link uses a scam TLD" in edited_text


@pytest.mark.asyncio
async def test_handle_text_analyzes_regular_messages():
    update = AsyncMock()
    update.message.text = "This is a test message"
    update.message.reply_text = AsyncMock()
    update.effective_message = update.message
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