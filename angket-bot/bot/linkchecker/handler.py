"""
bot/linkchecker/handler.py
===========================
Telegram wiring for URL checking. Thin on purpose — the real logic
lives in this package (lexical.py).

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
side, without the customer knowing."

That private DM shows who sent the link (full name, id) and when, a
compact verdict, and two buttons:
  - "See full details" / "🔼 Show less detail" — toggles the SAME message
    in place (edit_message_text) between the compact showcase and the
    full breakdown. No /start round-trip needed since we're already in
    the owner's DM.
  - "Delete" — removes that notification message. It only ever existed
    in the owner's own private chat with the bot, so deleting it is
    only ever "for the user" — nobody else could see it to begin with.

Key detail: we read `update.effective_message` instead of
`update.message`, because business messages arrive on
`update.business_message` — `update.message` is always None for those.
"""

from __future__ import annotations

import secrets
import time

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.error import TelegramError
from telegram.ext import ContextTypes

from bot.linkchecker.pipeline import (
    check_message_full,
    format_verdict_full,
    _risk_percent_and_label,
)
from bot.analysis.utils import log_url_scan
from bot.linkchecker.vectors import seed as seed_vectors

WELCOME_TEXT = (
    "🔗 **Link Scanner Bot**\n\n"
    "Drop a link in here (or in a group/business chat I'm in) and I'll flag "
    "sus ones automatically. Tap \"See full details\" on any showcase to get "
    "the full breakdown here in DM."
)

# How long a ticket (deep-link OR business-DM toggle state) stays valid.
TICKET_TTL_SECONDS = 60 * 60 * 24  # 24h


# ---------------------------------------------------------------------------
# Normal-chat flow: deep-link ticket store (bot_data, ticket -> full text).
# ---------------------------------------------------------------------------

def _tickets(context: ContextTypes.DEFAULT_TYPE) -> dict:
    """Shared (bot-wide) ticket store, NOT per-user.

    Why bot_data and not user_data: the person who taps "See full
    details" is not guaranteed to be the same Telegram user who
    triggered the check. bot_data is shared across every chat/user the
    bot talks to, so any deep link the bot itself generated can always
    be resolved.
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


# ---------------------------------------------------------------------------
# Business-DM flow: toggle ticket store (bot_data, ticket -> {short, full}).
# ---------------------------------------------------------------------------

def _business_tickets(context: ContextTypes.DEFAULT_TYPE) -> dict:
    return context.bot_data.setdefault("business_url_tickets", {})


def _stash_business_ticket(context: ContextTypes.DEFAULT_TYPE, short_text: str, full_text: str) -> str:
    tickets = _business_tickets(context)
    _prune_expired(tickets)
    ticket = secrets.token_hex(4)
    tickets[ticket] = {"short": short_text, "full": full_text, "ts": time.time()}
    return ticket


def _business_keyboard(ticket: str, showing_full: bool) -> InlineKeyboardMarkup:
    if showing_full:
        detail_button = InlineKeyboardButton("🔼 Show less detail", callback_data=f"u:l:{ticket}")
    else:
        detail_button = InlineKeyboardButton("🔍 See full details", callback_data=f"u:d:{ticket}")
    delete_button = InlineKeyboardButton("🗑️ Delete", callback_data=f"u:x:{ticket}")
    return InlineKeyboardMarkup([[detail_button, delete_button]])


async def handle_business_url_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles taps on the business-DM notification: detail toggle + delete."""
    query = update.callback_query
    if query is None or not query.data:
        return

    parts = query.data.split(":", 2)
    if len(parts) != 3 or parts[0] != "u":
        return
    action, ticket = parts[1], parts[2]

    entry = _business_tickets(context).get(ticket)
    if entry is None:
        await query.answer("This notification has expired.", show_alert=True)
        return

    if action == "x":
        await query.answer()
        try:
            await query.message.delete()
        except TelegramError:
            pass
        _business_tickets(context).pop(ticket, None)
        return

    if action == "d":
        text, keyboard = entry["full"], _business_keyboard(ticket, showing_full=True)
    elif action == "l":
        text, keyboard = entry["short"], _business_keyboard(ticket, showing_full=False)
    else:
        return

    await query.answer()
    await query.edit_message_text(
        text,
        parse_mode="Markdown",
        disable_web_page_preview=True,
        reply_markup=keyboard,
    )


# ---------------------------------------------------------------------------
# Shared formatting helpers.
# ---------------------------------------------------------------------------

def _showcase_text(verdicts: list[dict]) -> str:
    """Short, one-glance summary — the 'small showcase', not the full report."""
    if len(verdicts) == 1:
        v = verdicts[0]
        pct, _ = _risk_percent_and_label(v["score"])
        return f"{v['emoji']} *{v['label']}*  —  `{v['host']}`  ({pct}%)"
    lines = []
    for v in verdicts:
        pct, _ = _risk_percent_and_label(v["score"])
        lines.append(f"{v['emoji']} `{v['host']}` — {v['label']} ({pct}%)")
    return "\n".join(lines)


def _full_breakdown_text(verdicts: list[dict], include_evidence: bool = True) -> str:
    return "\n\n---\n\n".join(
        format_verdict_full(v, include_evidence=include_evidence) for v in verdicts
    )


def _sender_header(sender, sent_at) -> str:
    """Full name, id, and timestamp of whoever sent the link."""
    name = sender.full_name if sender else "Unknown sender"
    uid = sender.id if sender else "—"
    when = sent_at.strftime("%Y-%m-%d %H:%M UTC") if sent_at else "—"
    return f"👤 *{name}*  (`{uid}`)\n🕒 {when}"


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


# TODO(BB): dead code — bot.py wires /start to text_handler.start, which
# already reimplements ticket-resolution (see its docstring/comment in
# bot.py). Confirm with teammate before removing, or delete in a
# dedicated cleanup commit.
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/start — doubles as the deep-link landing page for the NORMAL-chat
    flow only (business-chat DMs toggle in place and never need /start).

    context.args carries the ticket when someone taps "See full details"
    on a showcase posted in a group or non-business DM.

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

    # Full pipeline: lexical + network trace + DNS/domain age + vector
    # search + LSH. Brand/phish vectors are seeded once per process.
    if not context.bot_data.get("_vectors_seeded"):
        seed_vectors()
        context.bot_data["_vectors_seeded"] = True

    # Network tracing can take a few seconds — show progress first
    # (normal chats only; business flow stays invisible).
    is_business = bool(message.business_connection_id)
    status = None if is_business else await message.reply_text("🔍 Checking link...", parse_mode="Markdown")

    verdicts = await check_message_full(message.text)
    if not verdicts:
        if status is not None:
            await status.delete()
        return  # this handler only speaks up when there's actually a link

    sender = update.effective_user
    for v in verdicts:
        log_url_scan(sender.id if sender else None, v["host"], v["score"], v["level"])

    # --- Business chat: stay invisible to the customer, DM the owner. ---
    if is_business:
        owner_chat_id = await _owner_chat_id(context, message.business_connection_id)
        if owner_chat_id is None:
            return  # can't resolve the owner right now — nothing safe to do

        header = f"👀 *New link detected in your business chat*\n\n{_sender_header(sender, message.date)}\n\n"
        short_text = header + _showcase_text(verdicts)
        full_text = header + _full_breakdown_text(verdicts)

        ticket = _stash_business_ticket(context, short_text, full_text)
        keyboard = _business_keyboard(ticket, showing_full=False)

        await context.bot.send_message(
            chat_id=owner_chat_id,
            text=short_text,
            parse_mode="Markdown",
            disable_web_page_preview=True,
            reply_markup=keyboard,
        )
        return

    # --- Private DM with the bot itself: full breakdown right away. ---
    # Already a 1:1 conversation, so there's no group to keep short for —
    # skip the deep-link ticket/button round-trip entirely.
    chat = update.effective_chat
    is_private = chat is not None and chat.type == "private"

    if is_private:
        # No Technical Evidence dump here — a direct DM paste wants the
        # clean report; that detail stays for the business/group flows,
        # which are reached via an explicit "see full details" tap.
        full = _full_breakdown_text(verdicts, include_evidence=False)
        await status.edit_text(
            full,
            parse_mode="Markdown",
            disable_web_page_preview=True,
        )
        return

    # --- Group/supergroup (channel as fallback): showcase in place, deep-link for details. ---
    full = _full_breakdown_text(verdicts)
    ticket = _stash_ticket(context, full)
    risky = any(v["level"] != "safe" for v in verdicts)
    label = "⚠️ Why is this sus?" if risky else "🔍 See full details"
    deep_link = f"https://t.me/{context.bot.username}?start={ticket}"
    keyboard = InlineKeyboardMarkup([[InlineKeyboardButton(label, url=deep_link)]])

    await status.edit_text(
        _showcase_text(verdicts),
        parse_mode="Markdown",
        disable_web_page_preview=True,  # don't preview a possibly-bad link
        reply_markup=keyboard,
    )
