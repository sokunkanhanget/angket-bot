"""
bot/handlers/url_handler.py
===========================
Telegram wiring for URL checking. Thin on purpose — the real logic
lives in bot/analysis/url_analyzer.py.

Two very different flows depending on where the link showed up:

NORMAL chat/group/DM
---------------------
  1. A link shows up.
  2. We post a short "showcase" verdict right where it was sent
     (edited in-place from a "Checking..." placeholder).
  3. The showcase has a button that deep-links into the bot's own DM
     (t.me/<bot_username>?start=<ticket>) for the full breakdown.

Telegram BUSINESS chat (secretary mode)
----------------------------------------
A business chat is a real conversation between the business owner and
their customer. Anything the bot sends there using the connection
(`business_connection_id`) is sent AS the business account and is
visible to BOTH sides — there is no "reply that only the owner sees"
within that chat. So for business messages we don't reply in the chat
at all. Instead we DM the business OWNER privately (their own private
chat with the bot — a totally separate chat the customer can't see),
using `BusinessConnection.user_chat_id`. That field is exactly what
Telegram provides for "tell the business owner something, off to the
side, without the customer knowing." The showcase + deep-link button
goes there instead.

Key detail: we read `update.effective_message` instead of
`update.message`, because business messages arrive on
`update.business_message` — `update.message` is always None for those.
For the normal-chat path, `effective_message.reply_text()` /
`.edit_text()` still forward `business_connection_id` automatically if
present (a PTB 22.x built-in) — but we intentionally avoid that path
for business messages per the above, and message the owner directly
instead.
"""

from __future__ import annotations

import secrets
import time

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.error import TelegramError
from telegram.ext import ContextTypes

from bot.analysis.url_analyzer import check_message, format_verdict
from bot.analysis.utils import log_url_scan

WELCOME_TEXT = (
    "🔗 **Link Scanner Bot**\n\n"
    "Drop a link in here (or in a group/business chat I'm in) and I'll flag "
    "sus ones automatically. Tap \"See full details\" on any showcase to get "
    "the full breakdown here in DM."
)

# How long a "See full details" ticket stays valid after being posted.
TICKET_TTL_SECONDS = 60 * 60 * 24  # 24h


def _tickets(context: ContextTypes.DEFAULT_TYPE) -> dict:
    """Shared (bot-wide) ticket store, NOT per-user.

    Why bot_data and not user_data: the person who taps "See full
    details" is not guaranteed to be the same Telegram user who
    triggered the check. In a business chat a customer might send the
    sus link, but it's the business owner who opens the bot's DM to
    review it — those are two different user_ids, so per-user storage
    (context.user_data) would fail to find the ticket. bot_data is
    shared across every chat/user the bot talks to, so any deep link
    the bot itself generated can always be resolved.
    """
    return context.bot_data.setdefault("url_tickets", {})


def _prune_expired(tickets: dict) -> None:
    now = time.time()
    for t in [t for t, v in tickets.items() if now - v["ts"] > TICKET_TTL_SECONDS]:
        tickets.pop(t, None)


def _stash_ticket(context: ContextTypes.DEFAULT_TYPE, full_text: str) -> str:
    tickets = _tickets(context)
    _prune_expired(tickets)
    ticket = secrets.token_hex(4)
    tickets[ticket] = {"text": full_text, "ts": time.time()}
    return ticket


def resolve_ticket(context: ContextTypes.DEFAULT_TYPE, ticket: str) -> str | None:
    """Look up a ticket's full breakdown. Used by /start below."""
    tickets = _tickets(context)
    _prune_expired(tickets)
    entry = tickets.get(ticket)
    return entry["text"] if entry else None


def _showcase_text(verdicts: list[dict]) -> str:
    """Short, one-glance summary — the 'small showcase', not the full report."""
    if len(verdicts) == 1:
        v = verdicts[0]
        return f"{v['emoji']} *{v['label']}*  —  `{v['host']}`"
    lines = [f"{v['emoji']} `{v['host']}` — {v['label']}" for v in verdicts]
    return "\n".join(lines)


def _build_ticket_and_keyboard(context: ContextTypes.DEFAULT_TYPE, verdicts: list[dict]):
    full = "\n\n---\n\n".join(format_verdict(v) for v in verdicts)
    ticket = _stash_ticket(context, full)
    risky = any(v["level"] != "safe" for v in verdicts)
    label = "⚠️ Why is this sus?" if risky else "🔍 See full details"
    deep_link = f"https://t.me/{context.bot.username}?start={ticket}"
    keyboard = InlineKeyboardMarkup([[InlineKeyboardButton(label, url=deep_link)]])
    return keyboard


async def _owner_chat_id(context: ContextTypes.DEFAULT_TYPE, business_connection_id: str) -> int | None:
    """Resolve a business connection to the OWNER's private chat id.

    `BusinessConnection.user_chat_id` is Telegram's built-in "message
    the business owner privately, off to the side" channel — separate
    from the actual business chat with the customer. We cache it in
    bot_data since it doesn't change for the lifetime of the
    connection; falls back to a live `getBusinessConnection` call
    (e.g. after a bot restart, before we've seen a fresh connect event).
    """
    cache = context.bot_data.setdefault("business_connections", {})
    if business_connection_id in cache:
        return cache[business_connection_id]
    try:
        conn = await context.bot.get_business_connection(business_connection_id)
    except TelegramError:
        return None
    cache[business_connection_id] = conn.user_chat_id
    return conn.user_chat_id


async def on_business_connection(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Keep the business-connection -> owner-chat-id cache warm.

    Fires when a business connection is created, its settings change,
    or it's revoked — register this on a BusinessConnectionHandler in
    bot.py so _owner_chat_id() rarely has to fall back to a live API call.
    """
    conn = update.business_connection
    if conn is None:
        return
    cache = context.bot_data.setdefault("business_connections", {})
    if conn.is_enabled:
        cache[conn.id] = conn.user_chat_id
    else:
        cache.pop(conn.id, None)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/start — doubles as the deep-link landing page.

    When someone taps "See full details" on a showcase, Telegram opens
    a DM with the bot and sends `/start <ticket>` automatically.
    context.args will contain that ticket — if present, show the full
    breakdown instead of the plain welcome message.

    NOTE: this owns the /start command for the links feature only.
    If a teammate's branch (file/text scanning) also wants to say
    something on /start, merge the two message bodies rather than
    registering two competing CommandHandler("start", ...) — PTB only
    calls the first one that matches.
    """
    if context.args:
        ticket = context.args[0]
        full = resolve_ticket(context, ticket)
        if full is None:
            await update.message.reply_text(
                "⌛ That result has expired. Send the link again to re-check it."
            )
            return
        await update.message.reply_text(
            full,
            parse_mode="Markdown",
            disable_web_page_preview=True,
        )
        return

    await update.message.reply_text(WELCOME_TEXT, parse_mode="Markdown")


async def handle_url(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # effective_message covers normal messages AND business messages.
    message = update.effective_message
    if message is None or message.text is None:
        return

    verdicts = check_message(message.text)
    if not verdicts:
        return  # this handler only speaks up when there's actually a link

    sender = update.effective_user
    for v in verdicts:
        log_url_scan(sender.id if sender else None, v["host"], v["score"], v["level"])

    # --- Business chat: stay invisible to the customer, DM the owner. ---
    if message.business_connection_id:
        owner_chat_id = await _owner_chat_id(context, message.business_connection_id)
        if owner_chat_id is None:
            return  # can't resolve the owner right now — nothing safe to do

        keyboard = _build_ticket_and_keyboard(context, verdicts)
        who = sender.first_name if sender else "Someone"
        text = f"👀 *{who}* sent a link in your business chat:\n\n{_showcase_text(verdicts)}"
        await context.bot.send_message(
            chat_id=owner_chat_id,
            text=text,
            parse_mode="Markdown",
            disable_web_page_preview=True,
            reply_markup=keyboard,
        )
        return

    # --- Normal chat/group/DM: showcase in place, as before. ---
    status = await message.reply_text("🔍 Checking link...", parse_mode="Markdown")
    keyboard = _build_ticket_and_keyboard(context, verdicts)
    await status.edit_text(
        _showcase_text(verdicts),
        parse_mode="Markdown",
        disable_web_page_preview=True,  # don't preview a possibly-bad link
        reply_markup=keyboard,
    )