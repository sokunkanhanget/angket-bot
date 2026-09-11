"""
tests/test_url_handler.py
=============================
Handler-level tests for bot/handlers/url_handler.py's handle_url -
the normal (non-Business-chat) group/supergroup link-check entrypoint.
Pipeline-level behavior (analyze_url, check_message_full's own merging
logic) is covered in tests/test_link_checker.py; Business-chat routing
is covered in tests/test_business_message.py. This file is specifically
for handle_url's own Telegram-wiring behavior.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bot.handlers.url_handler import handle_url
from bot.response.buttons import t
from bot.response.translate import DEFAULT_LANG
from bot.storage import subscription


def _group_update(text):
    update = MagicMock()
    update.effective_message.text = text
    update.effective_message.caption = None
    update.effective_message.business_connection_id = None
    update.effective_user = MagicMock(id=42, username=None)
    return update


def _context():
    context = MagicMock()
    context.bot_data = {"_vectors_seeded": True}
    context.user_data = {}
    return context


@pytest.mark.asyncio
async def test_handle_url_stops_animation_and_replies_on_unexpected_error():
    # Regression: check_message_full raising used to propagate straight
    # out of handle_url with the animation task never stopped - it would
    # keep editing the status message every 1.5s forever with no way to
    # reach it again, and the user would never get any reply at all. See
    # status_animation.py's own docstring for the underlying asyncio
    # gotcha this whole helper exists to avoid; text_handler.py's
    # handle_text had (and got fixed for) the same class of bug.
    update = _group_update("claim now http://free-prize-winner.tk/claim")
    context = _context()

    status_message = AsyncMock()
    update.effective_message.reply_text = AsyncMock(return_value=status_message)

    with patch("bot.handlers.url_handler.ensure_vectors_seeded", AsyncMock()), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(side_effect=RuntimeError("boom"))), \
         patch("bot.handlers.url_handler.stop_status_animation", AsyncMock()) as mock_stop:
        await handle_url(update, context)

    mock_stop.assert_awaited_once()
    status_message.edit_text.assert_awaited_once_with(t(DEFAULT_LANG, "scan_failed"))


@pytest.mark.asyncio
async def test_handle_url_checks_quota_before_seeding_vectors():
    # Regression: quota used to be checked AFTER ensure_vectors_seeded()
    # - a real Supabase call - so a sender who's already over their daily
    # limit still triggered it for nothing. handle_file/handle_text
    # already check quota first; this brings handle_url in line with
    # that same "quota gate is the first real work a handler does"
    # pattern instead of being the one inconsistent case.
    update = _group_update("claim now http://free-prize-winner.tk/claim")
    update.effective_message.reply_text = AsyncMock()
    context = _context()

    for _ in range(subscription.FREEMIUM_DAILY_LINKS_MESSAGES):
        subscription.record_link_or_message_scan(42)

    with patch("bot.handlers.url_handler.ensure_vectors_seeded", AsyncMock()) as mock_seed, \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock()) as mock_check:
        await handle_url(update, context)

    mock_seed.assert_not_awaited()
    mock_check.assert_not_awaited()
    update.effective_message.reply_text.assert_awaited_once_with(
        t(DEFAULT_LANG, "daily_scan_limit_reached").format(limit=subscription.FREEMIUM_DAILY_LINKS_MESSAGES)
    )
