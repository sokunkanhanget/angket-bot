"""
tests/test_route.py
=====================
Regression tests for routing behavior:

1. Caption blindness fix: a message that carries its scam text/link in
   a photo/document CAPTION (rather than plain .text) must not be
   invisible to the text/LLM scanner or the link checker - every filter
   used to check filters.TEXT only.

2. Context-engineering routing: plain PRIVATE chat is no longer
   suppressed by a link (handle_text reasons over text + link together
   itself - see bot/context_engine.py). GROUP/supergroup chat keeps the
   old two-independent-replies behavior, untouched.

3. Business chat automation: Business messages are now excluded from
   BOTH the old text scanner (TEXT_FILTER) and the old link checker
   (url_filter) entirely - they're fully owned by
   handle_business_message (bot.py group 3), which checks text, links,
   and files together in one call and reports privately to the owner.
"""

import datetime

from telegram import Chat, Message, Update
from telegram.ext import filters

from bot.bot import TEXT_FILTER

# Mirrors bot.py's url_filter exactly (group 1, handle_url).
URL_FILTER = (filters.TEXT | filters.CAPTION) & ~filters.COMMAND & ~filters.ChatType.PRIVATE


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


def test_url_filter_reaches_a_group_caption_containing_a_link():
    update = _update(
        caption="claim now http://free-prize-winner.tk/claim", chat_type=Chat.GROUP
    )
    assert bool(URL_FILTER.check_update(update))


def test_plain_private_chat_link_no_longer_suppresses_text_scanner():
    # This is the whole point of context-engineering: handle_text now
    # runs unconditionally in plain private chat, link or not, and
    # gathers/reasons over the link evidence itself.
    update = _update(text="claim now http://free-prize-winner.tk/claim")
    assert bool(TEXT_FILTER.check_update(update))


def test_plain_private_chat_link_is_excluded_from_the_old_link_checker():
    # The old, separate link-checker flow (handle_url) must stay out of
    # plain private chat now, or the same link would get a second,
    # uncoordinated reply alongside handle_text's unified one.
    update = _update(text="claim now http://free-prize-winner.tk/claim")
    assert not bool(URL_FILTER.check_update(update))


def test_business_chat_never_reaches_the_old_text_scanner():
    # Business chat is fully owned by handle_business_message now,
    # link or not - handle_text has no owner-DM logic and would either
    # duplicate the check or reply visibly in the business chat.
    update = _business_update(text="claim now http://free-prize-winner.tk/claim")
    assert not bool(TEXT_FILTER.check_update(update))

    update = _business_update(text="urgent, verify your account now")
    assert not bool(TEXT_FILTER.check_update(update))


def test_business_chat_never_reaches_the_old_link_checker():
    # Same reasoning: handle_business_message now checks links itself.
    update = _business_update(text="claim now http://free-prize-winner.tk/claim")
    assert not bool(URL_FILTER.check_update(update))


def test_group_chat_caption_link_does_not_suppress_text_scanner():
    # Group chat behavior is untouched by this pass: both scans still
    # run independently, same as before.
    update = _update(
        caption="claim now http://free-prize-winner.tk/claim",
        chat_type=Chat.GROUP,
    )
    assert bool(TEXT_FILTER.check_update(update))
