from unittest.mock import AsyncMock, patch

import pytest

from bot.response.buttons import key_for_label, label, t
from bot.handlers.text_handler import (
    MAIN_MENU_KEYBOARD,
    format_analysis_response,
    format_unified_response,
    get_language_keyboard,
    get_user_lang,
    handle_text,
)
from bot.storage import subscription
from bot.response.verdict_style import SECTION_DIVIDER


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
    assert "📁 <b>TYPE: text</b>" in response
    assert "🔍 <b>KEY REASONS</b>" in response
    assert "💡 <b>WHAT YOU SHOULD DO</b>" in response
    assert "• Uses an unrealistic offer &lt;now&gt;" in response
    assert "ⓘ Angket Bot may occasionally make mistakes." in response
    # Direct teammate feedback: a divider belongs directly ABOVE the
    # disclaimer specifically (not the earlier, since-removed stray
    # divider that sat somewhere else in the reply - see SECTION_DIVIDER's
    # own docstring in bot/response/verdict_style.py for that history).
    assert response.count(SECTION_DIVIDER) == 1
    assert f"{SECTION_DIVIDER}\nⓘ Angket Bot may occasionally make mistakes." in response
    assert "1. Verdict" not in response


def test_format_unified_response_type_line_reflects_what_was_actually_checked():
    # Direct user spec: the "📁 TYPE:" line replaces the old dedicated
    # file-name/type header - text/link/file combinations render as one
    # of exactly seven values (see verdict_style.scan_type_label).
    unified = {
        "verdict": "Scam", "risk_percentage": 95,
        "key_reasons": [{"text": "Attached file is malicious", "source": "file_evidence"}],
        "recommendations": ["Do not open the file"],
    }
    response = format_unified_response(
        unified, {"suspicious": False, "matches": []}, has_link=True, has_file=True, has_text=True
    )

    assert response.startswith(f"⚠️ <b>{t('en', 'verdict_label')}: {t('en', 'verdict_scam')}</b>\n")
    assert "📁 <b>TYPE: all</b>" in response


def test_format_unified_response_type_line_is_text_only_by_default():
    unified = {"verdict": "Not a Scam", "risk_percentage": 5, "key_reasons": [], "recommendations": []}
    response = format_unified_response(unified, {"suspicious": False, "matches": []})

    assert "📁 <b>TYPE: text</b>" in response
    assert response.startswith(f"✅ <b>{t('en', 'verdict_label')}")


def test_format_unified_response_shows_evidence_degraded_notice():
    # 2026-09-11 spec: a Supabase/vector-search outage that could
    # plausibly have mattered (see pipeline.py's analyze_url) appends a
    # small fixed notice, additive to the real reasons/recommendations.
    unified = {
        "verdict": "Uncertain", "risk_percentage": 40,
        "key_reasons": [{"text": "Some lexical concern", "source": None}],
        "recommendations": ["Be cautious"],
    }
    response = format_unified_response(
        unified, {"suspicious": False, "matches": []}, evidence_degraded=True,
    )

    assert t("en", "evidence_degraded_notice") in response
    # Still additive - the real reasons/recommendations are still there.
    assert "Some lexical concern" in response


def test_format_unified_response_omits_evidence_degraded_notice_by_default():
    unified = {"verdict": "Not a Scam", "risk_percentage": 5, "key_reasons": [], "recommendations": []}
    response = format_unified_response(unified, {"suspicious": False, "matches": []})

    assert t("en", "evidence_degraded_notice") not in response


def test_format_unified_response_shows_real_reasons_not_ai_unavailable_admission():
    # 2026-09-11 spec: a degraded (no-AI, ai_unavailable=True) result
    # shows _grounded_fallback's own real reasons/recommendations like
    # any other verdict - NOT the old "AI reasoning was unavailable"
    # generic notice, which used to replace the whole section.
    unified = {
        "verdict": "Uncertain", "risk_percentage": 60,
        "key_reasons": [{"text": "example.tk: flagged suspicious", "source": "link_evidence"}],
        "recommendations": ["Verify with the sender through a separate channel before acting."],
        "ai_unavailable": True,
    }
    response = format_unified_response(unified, {"suspicious": False, "matches": []})

    assert t("en", "ai_unavailable_notice") not in response
    # Domain wrapped non-clickable (2026-09-11 spec) - see defang_domains.
    assert "<code>example.tk</code>: flagged suspicious" in response
    assert "Verify with the sender through a separate channel before acting." in response


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
    update.effective_user.id = 42

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
    update.effective_user.id = 42
    return update


def _private_context():
    context = AsyncMock()
    context.bot_data = {"_vectors_seeded": True}  # skip real vector seeding
    return context


@pytest.mark.asyncio
async def test_handle_text_uses_unified_reasoning_in_plain_private_chat_no_link():
    # Plain private chat, no link: context-engineering path still fires
    # (unconditionally, per bot/context_engine/context_engine.py), just with zero link
    # evidence. A "Checking" status is still shown and then edited into
    # the verdict - analyze_unified (Gemini + bge-m3) is just as slow
    # here as the link/file path, so staying silent made the bot look
    # unresponsive on exactly this path (the real bug this test now guards).
    update = _private_update("free bitcoin now, click nowhere")
    context = _private_context()

    status_message = AsyncMock()
    update.message.reply_text = AsyncMock(return_value=status_message)

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
    update.message.reply_text.assert_awaited_once_with("🔍 Checking", parse_mode="Markdown")
    status_message.edit_text.assert_awaited_once()
    reply = status_message.edit_text.call_args[0][0]
    assert "VERDICT: LIKELY A SCAM" in reply
    assert "Promises free money" in reply


@pytest.mark.asyncio
async def test_handle_text_stops_animation_and_replies_on_unexpected_error():
    # Regression: analyze_unified (or format_unified_response/
    # record_link_or_message_scan) raising used to propagate straight out
    # of handle_text with the animation task never stopped - it would
    # keep editing the status message every 1.5s forever with no way to
    # reach it again, and the user would never get any reply at all. See
    # status_animation.py's own docstring for the underlying asyncio
    # gotcha this whole helper exists to avoid.
    update = _private_update("free bitcoin now, click nowhere")
    context = _private_context()

    status_message = AsyncMock()
    update.message.reply_text = AsyncMock(return_value=status_message)

    with patch("bot.handlers.text_handler.extract_text_link_entities", return_value=[]), patch(
        "bot.handlers.text_handler.check_message_full", AsyncMock(return_value=[])
    ), patch(
        "bot.handlers.text_handler.analyze_unified", AsyncMock(side_effect=RuntimeError("boom")),
    ), patch(
        "bot.handlers.text_handler.stop_status_animation", AsyncMock()
    ) as mock_stop:
        await handle_text(update, context)

    mock_stop.assert_awaited_once()
    status_message.edit_text.assert_awaited_once_with(t("en", "scan_failed"))


@pytest.mark.asyncio
async def test_usage_menu_button_shows_real_recorded_counts():
    # "usage" replaced "live_scan" as a main-menu item - unlike every
    # other menu item, its reply is dynamic (real numbers from
    # subscription.usage_summary(), which existed and was unit-tested
    # but never actually wired into a real reply before this). Records
    # real usage first so the reply can be checked against genuine
    # counts, not just "some text came back".
    update = _private_update(label("en", "usage"))
    context = _private_context()

    subscription.record_link_or_message_scan(update.effective_user.id)
    subscription.record_link_or_message_scan(update.effective_user.id)
    subscription.record_file_scan(update.effective_user.id)

    await handle_text(update, context)

    reply = update.message.reply_text.call_args[0][0]
    assert f"1/{subscription.FREEMIUM_DAILY_FILES}" in reply
    assert f"2/{subscription.FREEMIUM_DAILY_LINKS_MESSAGES}" in reply
    assert f"0/{subscription.FREEMIUM_DAILY_TOKENS}" in reply


@pytest.mark.asyncio
async def test_daily_scan_limit_blocks_before_any_real_work():
    update = _private_update("free bitcoin now, click nowhere")
    context = _private_context()
    for _ in range(subscription.FREEMIUM_DAILY_LINKS_MESSAGES):
        subscription.record_link_or_message_scan(update.effective_user.id)

    with patch("bot.handlers.text_handler.analyze_unified") as mock_unified, \
         patch("bot.handlers.text_handler.check_message_full") as mock_check:
        await handle_text(update, context)

    mock_unified.assert_not_called()
    mock_check.assert_not_called()
    update.message.reply_text.assert_awaited_once_with(
        t("en", "daily_scan_limit_reached").format(limit=subscription.FREEMIUM_DAILY_LINKS_MESSAGES),
        reply_markup=MAIN_MENU_KEYBOARD,
    )


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
    # A real string, not an AsyncMock's own auto-generated attribute -
    # format_unified_response's file-header block calls html.escape() on
    # this, which would crash on a coroutine-like mock object the same
    # way a real Telegram Document's file_name is always a real str|None.
    update.message.document.file_name = "invoice.pdf"
    context = _private_context()

    with patch("bot.handlers.text_handler.extract_text_link_entities", return_value=[]), patch(
        "bot.handlers.text_handler.check_message_full", AsyncMock(return_value=[])
    ), patch(
        "bot.handlers.text_handler.download_and_hash", AsyncMock(return_value="deadbeef")
    ), patch(
        "bot.handlers.text_handler.scan_file",
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

    update.message.reply_text.assert_awaited_once_with("🔍 Checking", parse_mode="Markdown")
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
    update.effective_user.id = 42
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