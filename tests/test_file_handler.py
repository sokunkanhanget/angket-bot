"""
tests/test_file_handler.py
============================
Tests for handle_file's scan-result buttons (Delete/Ignore/View on
VirusTotal - ported from panha's branch, adapted onto this codebase's
shared download_and_hash/scan_file/i18n/verdict_style) and
handle_scan_action_callback (the Delete/Ignore tap handler). No test
file existed for the direct (non-Business) file-scan path before this.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bot.handlers.file_handler import handle_file, handle_scan_action_callback
from bot.i18n import label, t
from bot.storage import subscription


def _file_update(lang: str | None = None, file_name: str = "invoice.pdf"):
    update = MagicMock()
    update.message.document = MagicMock(file_name=file_name, file_id="fake-file-id")
    update.message.message_id = 42
    update.effective_user = MagicMock(id=7)

    sent = MagicMock()
    sent.message_id = 99
    sent.edit_text = AsyncMock()
    update.message.reply_text = AsyncMock(return_value=sent)

    context = MagicMock()
    context.user_data = {"lang": lang} if lang else {}
    return update, context, sent


@pytest.mark.asyncio
async def test_clean_scan_shows_only_the_virustotal_button():
    update, context, sent = _file_update()

    with patch("bot.handlers.file_handler.download_and_hash", AsyncMock(return_value="a" * 64)), \
         patch("bot.handlers.file_handler.scan_file", AsyncMock(return_value={
             "found": True, "malicious": 0, "suspicious": 0, "harmless": 70,
             "undetected": 5, "total": 75,
             "top_engines": {"Microsoft": "Clean", "Kaspersky": "Clean", "BitDefender": "Clean"},
         })), \
         patch("bot.handlers.file_handler.log_scan"):
        await handle_file(update, context)

    keyboard = sent.edit_text.call_args.kwargs["reply_markup"]
    assert len(keyboard.inline_keyboard) == 1
    assert len(keyboard.inline_keyboard[0]) == 1
    assert keyboard.inline_keyboard[0][0].text == label("en", "view_on_virustotal")


@pytest.mark.asyncio
async def test_malicious_scan_shows_delete_ignore_and_virustotal_buttons():
    update, context, sent = _file_update(lang="km")

    with patch("bot.handlers.file_handler.download_and_hash", AsyncMock(return_value="b" * 64)), \
         patch("bot.handlers.file_handler.scan_file", AsyncMock(return_value={
             "found": True, "malicious": 40, "suspicious": 2, "harmless": 20,
             "undetected": 13, "total": 75,
             "top_engines": {"Microsoft": "Trojan", "Kaspersky": "Trojan", "BitDefender": "Trojan"},
         })), \
         patch("bot.handlers.file_handler.log_scan"):
        await handle_file(update, context)

    keyboard = sent.edit_text.call_args.kwargs["reply_markup"]
    assert len(keyboard.inline_keyboard) == 2
    delete_btn, ignore_btn = keyboard.inline_keyboard[0]
    assert delete_btn.text == label("km", "delete")
    assert delete_btn.callback_data == "delete_42"  # the ORIGINAL uploaded message, not the reply
    assert ignore_btn.text == label("km", "ignore")
    assert ignore_btn.callback_data == "ignore"
    assert keyboard.inline_keyboard[1][0].text == label("km", "view_on_virustotal")


@pytest.mark.asyncio
async def test_unknown_signature_still_offers_a_virustotal_link():
    update, context, sent = _file_update()

    with patch("bot.handlers.file_handler.download_and_hash", AsyncMock(return_value="c" * 64)), \
         patch("bot.handlers.file_handler.scan_file", AsyncMock(return_value={"found": False})), \
         patch("bot.handlers.file_handler.log_scan"):
        await handle_file(update, context)

    keyboard = sent.edit_text.call_args.kwargs["reply_markup"]
    assert len(keyboard.inline_keyboard) == 1
    assert keyboard.inline_keyboard[0][0].text == label("en", "view_on_virustotal")


@pytest.mark.asyncio
async def test_scan_failure_replies_gracefully_instead_of_crashing():
    # Regression: handle_file had no exception handling around
    # download_and_hash/scan_file at all - a genuine VirusTotal outage
    # (a raw network exception, not a vt.APIError scan_vt_hash already
    # catches) would propagate uncaught and crash the handler, leaving
    # the user with NO reply whatsoever.
    update, context, sent = _file_update()

    with patch("bot.handlers.file_handler.download_and_hash", AsyncMock(return_value="d" * 64)), \
         patch("bot.handlers.file_handler.scan_file", AsyncMock(side_effect=ConnectionError("VT unreachable"))), \
         patch("bot.handlers.file_handler.log_scan") as mock_log:
        await handle_file(update, context)

    sent.edit_text.assert_awaited_once_with(t("en", "file_scan_failed"))
    mock_log.assert_not_called()  # nothing to log - the scan never completed


@pytest.mark.asyncio
async def test_download_failure_also_replies_gracefully():
    update, context, sent = _file_update(lang="km")

    with patch("bot.handlers.file_handler.download_and_hash",
               AsyncMock(side_effect=TimeoutError("Telegram download timed out"))), \
         patch("bot.handlers.file_handler.log_scan") as mock_log:
        await handle_file(update, context)

    sent.edit_text.assert_awaited_once_with(t("km", "file_scan_failed"))
    mock_log.assert_not_called()


@pytest.mark.asyncio
async def test_daily_file_limit_blocks_scanning_once_reached():
    update, context, sent = _file_update()
    uid = update.effective_user.id
    for _ in range(subscription.FREEMIUM_DAILY_FILES):
        subscription.record_file_scan(uid)

    with patch("bot.handlers.file_handler.download_and_hash") as mock_download, \
         patch("bot.handlers.file_handler.scan_file") as mock_scan:
        await handle_file(update, context)

    mock_download.assert_not_called()  # never even started - blocked before any real work
    mock_scan.assert_not_called()
    update.message.reply_text.assert_awaited_once_with(
        t("en", "daily_file_limit_reached").format(limit=subscription.FREEMIUM_DAILY_FILES)
    )


@pytest.mark.asyncio
async def test_a_failed_scan_does_not_consume_the_daily_quota():
    # Fair to the user: a download/VT failure shouldn't burn one of
    # their limited daily scans.
    update, context, sent = _file_update()
    uid = update.effective_user.id

    with patch("bot.handlers.file_handler.download_and_hash",
               AsyncMock(side_effect=ConnectionError("VT unreachable"))), \
         patch("bot.handlers.file_handler.log_scan"):
        await handle_file(update, context)

    assert subscription.can_scan_file(uid)  # quota untouched by the failure
    summary = subscription.usage_summary(uid)
    assert summary["files_used"] == 0


def _callback_update(data: str, lang: str | None = None):
    update = MagicMock()
    update.callback_query.data = data
    update.callback_query.answer = AsyncMock()
    update.callback_query.edit_message_text = AsyncMock()
    update.callback_query.message.chat_id = 555

    context = MagicMock()
    context.user_data = {"lang": lang} if lang else {}
    context.bot.delete_message = AsyncMock()
    return update, context


@pytest.mark.asyncio
async def test_delete_removes_the_original_message_and_confirms():
    update, context = _callback_update("delete_42")

    await handle_scan_action_callback(update, context)

    context.bot.delete_message.assert_awaited_once_with(chat_id=555, message_id=42)
    update.callback_query.edit_message_text.assert_awaited_once_with(t("en", "file_deleted"))


@pytest.mark.asyncio
async def test_delete_failure_still_confirms_instead_of_crashing():
    from telegram.error import TelegramError

    update, context = _callback_update("delete_42")
    context.bot.delete_message = AsyncMock(side_effect=TelegramError("message to delete not found"))

    await handle_scan_action_callback(update, context)

    update.callback_query.edit_message_text.assert_awaited_once()


@pytest.mark.asyncio
async def test_ignore_confirms_without_deleting_anything():
    update, context = _callback_update("ignore", lang="km")

    await handle_scan_action_callback(update, context)

    context.bot.delete_message.assert_not_awaited()
    update.callback_query.edit_message_text.assert_awaited_once_with(t("km", "file_scan_ignored"))
