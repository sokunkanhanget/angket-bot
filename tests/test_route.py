"""
tests/test_route.py
=====================
Regression tests for routing behavior:

1. Caption blindness fix: a message that carries its scam text/link in
   a photo/document CAPTION (rather than plain .text) must not be
   invisible to the text/LLM scanner - every filter used to check
   filters.TEXT only.

2. Context-engineering routing: plain PRIVATE chat is no longer
   suppressed by a link (handle_text reasons over text + link together
   itself - see bot/context_engine/context_engine.py).

3. Business chat automation: Business messages are excluded from the
   text scanner (TEXT_FILTER) entirely - fully owned by
   handle_business_message (bot.py group 3), which checks text, links,
   and files together in one call and reports privately to the owner.

4. GROUP/supergroup chat: no live/unprompted scanning at all as of
   2026-09-19 (a teammate reported the bot auto-scanning every group
   message, which wasn't wanted). /check (ChatType.GROUPS-only
   CommandHandler) is the sole group-scanning entry point now; the old
   always-on group auto-scan (a separate handle_url MessageHandler,
   plus TEXT_FILTER matching GROUPS too) has been removed entirely.

5. Group command exposure: also as of 2026-09-19, a group only ever
   exposes /check, /howto, /policy - /language, /usage, /subscription
   are private-account concepts with no group equivalent. Real gating
   happens at bot.py's CommandHandler filter registration (per command,
   picked from _GROUP_ALLOWED_COMMANDS), NOT inside handle_command
   itself, which has no chat-type awareness of its own for this - a
   test against handle_command's behavior directly would pass even if
   the real filter regressed, so this is tested at the filter/constant
   level instead, same reasoning as TEXT_FILTER above.
"""

import datetime

from telegram.ext import filters

from telegram import Chat, Message, Update

from bot.bot import COMMAND_KEYS, TEXT_FILTER, _GROUP_ALLOWED_COMMANDS, _PRIVATE_CHAT_ONLY


def _update(caption=None, text=None, chat_type=Chat.PRIVATE, message_id=1):
    chat = Chat(id=1, type=chat_type)
    message = Message(
        message_id=message_id,
        date=datetime.datetime.now(),
        chat=chat,
        caption=caption,
        text=text,
    )
    return Update(update_id=message_id, message=message)


def _business_update(caption=None, text=None, message_id=1):
    # Business messages arrive on update.business_message, not
    # update.message - and always have chat.type == "private".
    chat = Chat(id=1, type=Chat.PRIVATE)
    message = Message(
        message_id=message_id,
        date=datetime.datetime.now(),
        chat=chat,
        caption=caption,
        text=text,
        business_connection_id="conn1",
    )
    return Update(update_id=message_id, business_message=message)


def test_text_filter_reaches_a_caption_with_no_link():
    # A photo/document caption with scam wording and no link must still
    # reach the text/LLM scanner - previously invisible entirely.
    update = _update(caption="urgent, verify your account now")
    assert bool(TEXT_FILTER.check_update(update))


def test_plain_private_chat_link_no_longer_suppresses_text_scanner():
    # This is the whole point of context-engineering: handle_text now
    # runs unconditionally in plain private chat, link or not, and
    # gathers/reasons over the link evidence itself.
    update = _update(text="claim now http://free-prize-winner.tk/claim")
    assert bool(TEXT_FILTER.check_update(update))


def test_business_chat_never_reaches_the_old_text_scanner():
    # Business chat is fully owned by handle_business_message now,
    # link or not - handle_text has no owner-DM logic and would either
    # duplicate the check or reply visibly in the business chat.
    update = _business_update(text="claim now http://free-prize-winner.tk/claim")
    assert not bool(TEXT_FILTER.check_update(update))

    update = _business_update(text="urgent, verify your account now")
    assert not bool(TEXT_FILTER.check_update(update))


def test_group_chat_no_longer_reaches_the_text_scanner():
    # 2026-09-19: group auto-scan removed - /check is the only way to
    # scan a group message now, live or not, link or not.
    update = _update(
        caption="claim now http://free-prize-winner.tk/claim",
        chat_type=Chat.GROUP,
    )
    assert not bool(TEXT_FILTER.check_update(update))

    update = _update(text="urgent, verify your account now", chat_type=Chat.SUPERGROUP)
    assert not bool(TEXT_FILTER.check_update(update))


def test_group_command_exposure_matches_the_direct_user_spec():
    assert _GROUP_ALLOWED_COMMANDS == {"howto", "policy"}

    for command in COMMAND_KEYS:
        filt = ~filters.ChatType.CHANNEL if command in _GROUP_ALLOWED_COMMANDS else _PRIVATE_CHAT_ONLY
        group_update = _update(text=f"/{command}", chat_type=Chat.SUPERGROUP)
        private_update = _update(text=f"/{command}", chat_type=Chat.PRIVATE)
        if command in _GROUP_ALLOWED_COMMANDS:
            assert bool(filt.check_update(group_update)), command
        else:
            assert not bool(filt.check_update(group_update)), command
        # Every command must still reach private chat regardless - only
        # GROUP exposure is being restricted here.
        assert bool(filt.check_update(private_update)), command
