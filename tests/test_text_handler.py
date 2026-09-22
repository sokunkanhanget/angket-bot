from unittest.mock import AsyncMock, patch

import pytest
from telegram.error import TelegramError

from bot.response.buttons import key_for_label, label, t
from bot.response.translate import DEFAULT_LANG
from bot.handlers.text_handler import (
    MAIN_MENU_KEYBOARD,
    format_analysis_response,
    format_unified_response,
    get_language_keyboard,
    get_user_lang,
    handle_check,
    handle_command,
    handle_text,
    handle_website,
)
from bot.storage import subscription


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
    assert "─" not in response
    assert "\n\nⓘ Angket Bot may occasionally make mistakes." in response
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


@pytest.mark.asyncio
async def test_get_user_lang_defaults_and_persists_context():
    context = type("Ctx", (), {"user_data": {}})()
    assert await get_user_lang(context, 1) == "en"

    context.user_data["lang"] = "km"
    assert await get_user_lang(context, 1) == "km"


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
    #
    # Retargeted 2026-09-19: this used to patch analyze_text_with_llm
    # because the fake update's bare AsyncMock effective_chat.type never
    # equaled "private", so it fell into handle_text's old group-chat
    # branch by accident - that branch is now deleted (dead code, since
    # TEXT_FILTER excludes GROUPS too), so this must go through the real,
    # only remaining path (analyze_unified) like every other private-DM
    # test in this file, with effective_chat.type set explicitly.
    update = AsyncMock()
    update.message.text = None
    update.message.caption = "URGENT: verify your account now or it will be suspended"
    update.message.document = None
    update.message.business_connection_id = None
    update.message.reply_text = AsyncMock()
    update.effective_message = update.message
    update.effective_chat.type = "private"
    update.effective_user.id = 42
    context = _private_context()

    with patch("bot.handlers.text_handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.handlers.text_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.text_handler.check_message_full", AsyncMock(return_value=[])), \
         patch(
        "bot.handlers.text_handler.analyze_unified",
        AsyncMock(return_value={
            "verdict": "Scam",
            "risk_percentage": 80,
            "key_reasons": [{"text": "Urgent request", "source": "message_text"}],
            "recommendations": ["Be careful"],
        }),
    ):
        await handle_text(update, context)

    update.message.reply_text.assert_awaited_once()
    assert "🔍 Checking" in update.message.reply_text.call_args[0][0]


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


def _group_check_update(reply_to_text=None, args=None, reply_to_document=None, has_reply=False):
    update = AsyncMock()
    message = update.effective_message
    message.reply_text = AsyncMock()
    if has_reply or reply_to_text is not None or reply_to_document is not None:
        message.reply_to_message.text = reply_to_text
        message.reply_to_message.caption = None
        message.reply_to_message.document = reply_to_document
    else:
        message.reply_to_message = None
    update.effective_chat.type = "supergroup"
    update.effective_user.id = 42
    context = AsyncMock()
    context.args = args or []
    context.bot_data = {"_vectors_seeded": True}
    # Same fix as _private_context - user_data is a plain dict in real
    # python-telegram-bot. handle_check itself never reads it today
    # (group chat stays DEFAULT_LANG by design), but leaving it as
    # AsyncMock's default child mock is a live trap for whenever that
    # changes, and costs nothing to fix now.
    context.user_data = {}
    return update, context


def _private_context():
    context = AsyncMock()
    context.bot_data = {"_vectors_seeded": True}  # skip real vector seeding
    # Regression: user_data is a plain dict in real python-telegram-bot,
    # never an async API - left as AsyncMock's default child mock, every
    # test using this fixture silently fed get_user_lang() a coroutine
    # object instead of a string. get_user_lang does str(<coroutine>),
    # which is truthy and non-empty, so the lookup didn't crash - it just
    # returned garbage that happened to fall through t()'s own "or
    # DEFAULT_LANG" fallback to the same English text these tests were
    # already asserting on. So every test using this fixture passed for
    # the wrong reason, not exercising the real "read context.user_data"
    # path at all. A real dict makes it genuinely exercised.
    context.user_data = {}
    return context


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("/language", "Switch Language"),
        ("/howto", "How to Use Angket Bot"),
        ("/usage", "Daily Usage"),
        ("/policy", "Angket Bot Policy"),
        ("/subscription", "View Premium Plans"),
    ],
)
async def test_handle_command_dispatches_help_commands(command, expected):
    update = _private_update(command)
    context = _private_context()

    await handle_command(update, context)

    response = update.message.reply_text.call_args[0][0]
    assert expected in response


@pytest.mark.asyncio
async def test_handle_website_sends_an_external_link_button():
    # Direct user spec, 2026-09-21: a plain URL button, not a Telegram
    # Mini App/WebAppInfo - tapping it opens the real site in the user's
    # own browser, no round trip back to the bot at all.
    update = _private_update("/website")
    context = _private_context()

    await handle_website(update, context)

    update.message.reply_text.assert_awaited_once()
    _, kwargs = update.message.reply_text.await_args
    keyboard = kwargs["reply_markup"]
    button = keyboard.inline_keyboard[0][0]
    assert button.url == "https://angket-website.vercel.app"
    assert button.callback_data is None  # a URL button never round-trips to the bot


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("/howto", "How to Use Angket Bot in a Group"),
        ("/policy", "Angket Bot Policy"),
    ],
)
async def test_handle_command_in_group_shows_group_variant_with_no_menu_keyboard(command, expected):
    # Direct user spec, 2026-09-19: group chat only ever exposes /check,
    # /howto, /policy - main_menu_keyboard (Switch Language/Usage/etc.)
    # would show buttons that silently do nothing in a group now (button
    # taps route through handle_text, which is private-only), so it must
    # be suppressed there. /howto also gets a /check-focused variant
    # instead of the private-chat "send content directly" text, which
    # doesn't apply in a group at all.
    update = _group_check_update(reply_to_text=None)[0]
    update.effective_message.text = command
    update.message = update.effective_message
    context = _group_check_update()[1]

    await handle_command(update, context)

    response = update.effective_message.reply_text.call_args[0][0]
    assert expected in response
    _, kwargs = update.effective_message.reply_text.await_args
    assert kwargs["reply_markup"] is None


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

    await subscription.record_link_or_message_scan(update.effective_user.id)
    await subscription.record_link_or_message_scan(update.effective_user.id)
    await subscription.record_file_scan(update.effective_user.id)

    await handle_text(update, context)

    reply = update.message.reply_text.call_args[0][0]
    assert f"1/{subscription.FREEMIUM_DAILY_FILES}" in reply
    assert f"2/{subscription.FREEMIUM_DAILY_LINKS_MESSAGES}" in reply
    assert f"0/{subscription.FREEMIUM_DAILY_TOKENS:,} tokens" in reply


@pytest.mark.asyncio
async def test_daily_scan_limit_blocks_before_any_real_work():
    update = _private_update("free bitcoin now, click nowhere")
    context = _private_context()
    for _ in range(subscription.FREEMIUM_DAILY_LINKS_MESSAGES):
        await subscription.record_link_or_message_scan(update.effective_user.id)

    # extract_text_link_entities now runs BEFORE the quota gate too
    # (unavoidable - the gate needs it for the bare_trusted_link shape
    # check, see handle_text's own comment); it's a pure local entity
    # parse, not real work. What must still never happen is the real
    # (billable) pipeline/Gemini call.
    with patch("bot.handlers.text_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.text_handler.analyze_unified") as mock_unified, \
         patch("bot.handlers.text_handler.check_message_full") as mock_check:
        await handle_text(update, context)

    mock_unified.assert_not_called()
    mock_check.assert_not_called()
    update.message.reply_text.assert_awaited_once_with(
        t("en", "daily_scan_limit_reached").format(
            limit=subscription.FREEMIUM_DAILY_LINKS_MESSAGES,
            reset_time=subscription.reset_time_display(),
        ),
        reply_markup=MAIN_MENU_KEYBOARD,
        parse_mode="HTML",
    )


@pytest.mark.asyncio
async def test_daily_scan_limit_only_notifies_once_in_private_dm():
    # Direct user spec (2026-09-15): tell them once, not on every message
    # they send while still over today's limit.
    update = _private_update("free bitcoin now, click nowhere")
    context = _private_context()
    for _ in range(subscription.FREEMIUM_DAILY_LINKS_MESSAGES):
        await subscription.record_link_or_message_scan(update.effective_user.id)

    with patch("bot.handlers.text_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.text_handler.analyze_unified") as mock_unified, \
         patch("bot.handlers.text_handler.check_message_full") as mock_check:
        await handle_text(update, context)  # 1st over-quota message: notified
        update.message.reply_text.assert_awaited_once()
        update.message.reply_text.reset_mock()

        await handle_text(update, context)  # 2nd over-quota message: silent

    mock_unified.assert_not_called()
    mock_check.assert_not_called()
    update.message.reply_text.assert_not_called()


@pytest.mark.asyncio
async def test_handle_text_private_dm_genuinely_reads_khmer_from_user_data():
    # Regression for the AsyncMock-user_data bug fixed in _private_context
    # above: with that bug, get_user_lang(context) returned
    # str(<coroutine>) instead of "km", which is not "km" or "en" either -
    # t()'s own "or DEFAULT_LANG" fallback then silently rendered English
    # anyway, so every _private_context()-based test passed for the wrong
    # reason without ever really exercising the Khmer path. This sets a
    # REAL km value in a real dict and asserts the actual verdict text -
    # not just the fixed VERDICT/TYPE labels, which route through
    # verdict_style.py separately - comes back in Khmer, proving
    # get_user_lang's return value genuinely reaches Gemini's language
    # instruction and back into the reply.
    update = _private_update("free bitcoin now, click nowhere")
    context = _private_context()
    context.user_data["lang"] = "km"

    with patch("bot.handlers.text_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.text_handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam",
             "risk_percentage": 90,
             "key_reasons": [{"text": "លុយឥតគិតថ្លៃមិនមែនជារឿងពិតទេ", "source": "message_text"}],
             "recommendations": ["កុំចុចលីង"],
         })) as mock_unified:
        await handle_text(update, context)

    mock_unified.assert_awaited_once()
    # analyze_unified(text, keyword_result, link_verdicts, file_verdict,
    # lang, user_id) - the 5th positional arg must be the real "km", not
    # a coroutine's string form.
    assert mock_unified.call_args.args[4] == "km"
    status_message = update.message.reply_text.return_value
    reply = status_message.edit_text.call_args[0][0]
    assert "លុយឥតគិតថ្លៃមិនមែនជារឿងពិតទេ" in reply
    assert "ទំនងជាការឆបោក" in reply  # verdict_style's own Khmer "Scam" label


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
    # Retargeted 2026-09-19: see test_handle_text_analyzes_a_caption_when_
    # text_is_absent's comment - the old group-chat branch this used to
    # exercise via a bare AsyncMock (accidentally not "private") is now
    # deleted dead code, so this goes through the real analyze_unified
    # path instead, with effective_chat.type set explicitly.
    update = AsyncMock()
    update.message.text = "This is a test message"
    update.message.document = None
    update.message.business_connection_id = None
    update.message.reply_text = AsyncMock()
    update.effective_message = update.message
    update.effective_chat.type = "private"
    update.effective_user.id = 42
    context = _private_context()

    with patch("bot.handlers.text_handler.analyze_text", return_value={"suspicious": False, "matches": []}), \
         patch("bot.handlers.text_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.text_handler.check_message_full", AsyncMock(return_value=[])), \
         patch(
        "bot.handlers.text_handler.analyze_unified",
        AsyncMock(return_value={
            "verdict": "Scam",
            "risk_percentage": 90,
            "key_reasons": [{"text": "Urgent request", "source": "message_text"}],
            "recommendations": ["Be careful"],
        }),
    ):
        await handle_text(update, context)

    update.message.reply_text.assert_awaited_once_with("🔍 Checking", parse_mode="Markdown")


@pytest.mark.asyncio
async def test_handle_check_shows_usage_hint_with_no_reply_and_no_args():
    update, context = _group_check_update()

    await handle_check(update, context)

    update.effective_message.reply_text.assert_awaited_once_with(t(DEFAULT_LANG, "check_usage_hint"))


@pytest.mark.asyncio
async def test_handle_check_shows_nothing_to_check_when_reply_has_no_text_or_document():
    update, context = _group_check_update(has_reply=True)

    with patch("bot.handlers.text_handler.extract_text_link_entities", return_value=[]):
        await handle_check(update, context)

    update.effective_message.reply_text.assert_awaited_once_with(t(DEFAULT_LANG, "check_nothing_to_check"))


@pytest.mark.asyncio
async def test_handle_check_blocked_by_daily_quota():
    update, context = _group_check_update(args=["http://example.com"])
    for _ in range(subscription.FREEMIUM_DAILY_LINKS_MESSAGES):
        await subscription.record_link_or_message_scan(42)

    with patch("bot.handlers.text_handler.ensure_vectors_seeded", AsyncMock()) as mock_seed, \
         patch("bot.handlers.text_handler.check_message_full", AsyncMock()) as mock_check:
        await handle_check(update, context)

    mock_seed.assert_not_awaited()
    mock_check.assert_not_awaited()
    update.effective_message.reply_text.assert_awaited_once_with(
        t(DEFAULT_LANG, "daily_scan_limit_reached").format(
            limit=subscription.FREEMIUM_DAILY_LINKS_MESSAGES,
            reset_time=subscription.reset_time_display(),
        ),
        reply_markup=None,
        parse_mode="HTML",
    )


@pytest.mark.asyncio
async def test_handle_check_only_notifies_once():
    # Same notify-once contract as handle_text's private-DM path, and
    # the SAME shared per-user counter - proven here by exhausting the
    # quota via handle_text's own uid (42) and confirming /check's first
    # call is still silent because handle_text already spent today's
    # notification.
    update = _private_update("free bitcoin now, click nowhere")
    private_context = _private_context()
    for _ in range(subscription.FREEMIUM_DAILY_LINKS_MESSAGES):
        await subscription.record_link_or_message_scan(42)
    with patch("bot.handlers.text_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.text_handler.analyze_unified"), \
         patch("bot.handlers.text_handler.check_message_full"):
        await handle_text(update, private_context)
    update.message.reply_text.assert_awaited_once()  # sanity: private DM got the one notification

    check_update, check_context = _group_check_update(args=["http://example.com"])
    with patch("bot.handlers.text_handler.ensure_vectors_seeded", AsyncMock()), \
         patch("bot.handlers.text_handler.check_message_full", AsyncMock()):
        await handle_check(check_update, check_context)

    check_update.effective_message.reply_text.assert_not_called()


@pytest.mark.asyncio
async def test_handle_check_checks_quota_before_seeding_vectors():
    # Same fix already applied to handle_url (test_handle_url_checks_
    # quota_before_seeding_vectors) - a real Supabase call shouldn't
    # happen for an already-over-quota sender.
    update, context = _group_check_update(args=["free prize claim now"])
    for _ in range(subscription.FREEMIUM_DAILY_LINKS_MESSAGES):
        await subscription.record_link_or_message_scan(42)

    with patch("bot.handlers.text_handler.ensure_vectors_seeded", AsyncMock()) as mock_seed:
        await handle_check(update, context)

    mock_seed.assert_not_awaited()


@pytest.mark.asyncio
async def test_handle_check_full_flow_via_reply():
    # Direct user spec, 2026-09-19: the verdict goes to the CALLER's own
    # private chat with the bot (context.bot.send_message), not into the
    # group at all - supersedes an earlier same-day fix that threaded it
    # onto the original flagged message in-group instead.
    update, context = _group_check_update(reply_to_text="free bitcoin now, click nowhere")
    status_message = AsyncMock()
    context.bot.send_message = AsyncMock(return_value=status_message)

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
        await handle_check(update, context)

    mock_unified.assert_awaited_once()
    context.bot.send_message.assert_awaited_once()
    assert context.bot.send_message.call_args.kwargs["chat_id"] == 42
    update.effective_message.reply_text.assert_not_called()
    update.effective_message.reply_to_message.reply_text.assert_not_called()
    status_message.edit_text.assert_awaited_once()
    reply = status_message.edit_text.call_args[0][0]
    assert "VERDICT: LIKELY A SCAM" in reply
    assert "Promises free money" in reply


@pytest.mark.asyncio
async def test_handle_check_falls_back_to_group_when_dm_never_delivers():
    # Direct user spec, 2026-09-19: if the caller has never started a
    # private chat with the bot, Telegram refuses to let the bot DM them
    # ("bot can't initiate conversation") - context.bot.send_message
    # raises TelegramError both attempts (retried once), so this must
    # fall back to replying in the group instead of losing the check
    # entirely or failing silently. Reply mode falls back onto the
    # ORIGINAL flagged message, same as the pre-DM-redirect behavior.
    update, context = _group_check_update(reply_to_text="free bitcoin now, click nowhere")
    context.bot.send_message = AsyncMock(side_effect=TelegramError("bot can't initiate conversation"))
    fallback_status = AsyncMock()
    update.effective_message.reply_to_message.reply_text = AsyncMock(return_value=fallback_status)

    with patch("bot.handlers.text_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.text_handler.check_message_full", AsyncMock(return_value=[])), \
         patch(
        "bot.handlers.text_handler.analyze_unified",
        AsyncMock(return_value={
            "verdict": "Scam", "risk_percentage": 90,
            "key_reasons": [{"text": "Promises free money", "source": "message_text"}],
            "recommendations": ["Ignore it"],
        }),
    ):
        await handle_check(update, context)

    assert context.bot.send_message.await_count == 2  # one attempt + one retry
    update.effective_message.reply_to_message.reply_text.assert_awaited_once()
    fallback_status.edit_text.assert_awaited_once()
    assert "VERDICT: LIKELY A SCAM" in fallback_status.edit_text.call_args[0][0]


@pytest.mark.asyncio
async def test_handle_check_dm_succeeds_on_retry_after_one_failure():
    update, context = _group_check_update(args=["http://bit.ly/scam-test"])
    status_message = AsyncMock()
    context.bot.send_message = AsyncMock(side_effect=[TelegramError("temporary"), status_message])

    with patch("bot.handlers.text_handler.check_message_full", AsyncMock(return_value=[])), patch(
        "bot.handlers.text_handler.analyze_unified",
        AsyncMock(return_value={
            "verdict": "Not a Scam", "risk_percentage": 5, "key_reasons": [], "recommendations": [],
        }),
    ):
        await handle_check(update, context)

    assert context.bot.send_message.await_count == 2
    update.effective_message.reply_text.assert_not_called()
    status_message.edit_text.assert_awaited_once()


@pytest.mark.asyncio
async def test_handle_check_standalone_with_args():
    # Standalone-args mode also goes to DM, same as reply mode - see
    # test_handle_check_full_flow_via_reply's comment.
    update, context = _group_check_update(args=["http://bit.ly/scam-test"])
    status_message = AsyncMock()
    context.bot.send_message = AsyncMock(return_value=status_message)

    with patch("bot.handlers.text_handler.check_message_full", AsyncMock(return_value=[])) as mock_check, patch(
        "bot.handlers.text_handler.analyze_unified",
        AsyncMock(return_value={
            "verdict": "Not a Scam", "risk_percentage": 5, "key_reasons": [], "recommendations": [],
        }),
    ):
        await handle_check(update, context)

    mock_check.assert_awaited_once_with("http://bit.ly/scam-test", [])
    status_message.edit_text.assert_awaited_once()


def _trusted_verdict(**over):
    v = {"host": "facebook.com", "score": 0, "level": "safe", "reasons": [],
         "detail": [], "trusted_brand": True}
    v.update(over)
    return v


_NOT_A_SCAM = {"verdict": "Not a Scam", "risk_percentage": 0, "key_reasons": [], "recommendations": []}

# What the REAL _trusted_bare_link_verdict short-circuit actually returns
# for a bare trusted-brand link (see context_engine.py) - a plain
# _NOT_A_SCAM mock has no trusted_link_notice_host key, so it can't
# stand in for this specific case since 2026-09-16's lightweight-notice
# change; that key is what now decides both the quota skip AND the
# reply shape.
_TRUSTED_NOTICE = {**_NOT_A_SCAM, "trusted_link_notice_host": "facebook.com"}


@pytest.mark.asyncio
async def test_handle_check_bare_trusted_link_skips_quota_even_when_over_limit():
    update, context = _group_check_update(args=["https://facebook.com"])
    for _ in range(subscription.FREEMIUM_DAILY_LINKS_MESSAGES):
        await subscription.record_link_or_message_scan(42)
    used_before = (await subscription.usage_summary(42))["links_messages_used"]
    status_message = AsyncMock()
    context.bot.send_message = AsyncMock(return_value=status_message)

    with patch("bot.handlers.text_handler.check_message_full",
               AsyncMock(return_value=[_trusted_verdict()])), \
         patch("bot.handlers.text_handler.analyze_unified", AsyncMock(return_value=_TRUSTED_NOTICE)):
        await handle_check(update, context)

    # Never blocked - status message got a real edit, not the quota-limit reply.
    status_message.edit_text.assert_awaited_once()
    reply = status_message.edit_text.call_args[0][0]
    assert "facebook.com" in reply
    assert "VERDICT" not in reply  # the lightweight notice, not the full template
    assert (await subscription.usage_summary(42))["links_messages_used"] == used_before


@pytest.mark.asyncio
async def test_handle_check_shape_match_but_unsafe_verdict_still_charges_quota():
    update, context = _group_check_update(args=["https://facebook.com"])
    status_message = AsyncMock()
    update.effective_message.reply_text = AsyncMock(return_value=status_message)

    with patch("bot.handlers.text_handler.check_message_full",
               AsyncMock(return_value=[_trusted_verdict(level="suspicious", score=20)])), \
         patch("bot.handlers.text_handler.analyze_unified", AsyncMock(return_value=_NOT_A_SCAM)):
        await handle_check(update, context)

    assert (await subscription.usage_summary(42))["links_messages_used"] == 1


@pytest.mark.asyncio
async def test_handle_text_private_bare_trusted_link_skips_quota_even_when_over_limit():
    update = _private_update("https://facebook.com")
    context = _private_context()
    for _ in range(subscription.FREEMIUM_DAILY_LINKS_MESSAGES):
        await subscription.record_link_or_message_scan(42)
    used_before = (await subscription.usage_summary(42))["links_messages_used"]
    status_message = AsyncMock()
    update.message.reply_text = AsyncMock(return_value=status_message)

    with patch("bot.handlers.text_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.text_handler.ensure_vectors_seeded", AsyncMock()), \
         patch("bot.handlers.text_handler.check_message_full",
               AsyncMock(return_value=[_trusted_verdict()])), \
         patch("bot.handlers.text_handler.analyze_unified", AsyncMock(return_value=_TRUSTED_NOTICE)):
        await handle_text(update, context)

    status_message.edit_text.assert_awaited_once()
    reply = status_message.edit_text.call_args[0][0]
    assert "facebook.com" in reply
    assert "VERDICT" not in reply  # the lightweight notice, not the full template
    assert (await subscription.usage_summary(42))["links_messages_used"] == used_before