"""
bot/url_checker/message/handler.py
====================================
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

import asyncio
import logging
import secrets
import time

from telegram import MessageEntity, Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.error import TelegramError
from telegram.ext import ContextTypes

from bot.analysis.file_scanner import download_and_hash, scan_vt_hash
from bot.analysis.text_analyzer import analyze_text
from bot.context_engine import analyze_unified
from bot.i18n import DEFAULT_LANG, t
from bot.url_checker.pipeline import (
    check_message_full,
    format_verdict_full,
    _risk_percent_and_label,
)
from bot.verdict_style import SOURCE_TAGS, risk_style, verdict_style
from bot.analysis.utils import log_url_scan
from bot.url_checker.features.offline.vectors import ensure_seeded as ensure_vectors_seeded

logger = logging.getLogger(__name__)

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
    for ticket_id in [k for k, v in tickets.items() if now - v["ts"] > TICKET_TTL_SECONDS]:
        tickets.pop(ticket_id, None)


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


def _owner_lang(context: ContextTypes.DEFAULT_TYPE, owner_chat_id: int) -> str:
    """The business-owner-DM notification is read only by the OWNER, never
    the customer - so it must translate based on the OWNER's language
    preference, not whatever context.user_data the current (customer's)
    update happens to carry. A private chat_id equals that user's own
    user_id in Telegram, and PTB keeps one shared user_data store keyed
    by user_id across every chat that user touches (Application.user_data,
    a read-only Mapping - not context.user_data, which is scoped to the
    CURRENT update's effective_user). If the owner has ever run /start
    and switched language in their own private chat with the bot, it's
    already sitting under this same key - no new state needed. Falls back
    to English if they never have."""
    owner_data = context.application.user_data.get(owner_chat_id) or {}
    return owner_data.get("lang", DEFAULT_LANG)


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


# TODO(BB): dead code — bot.py wires /start to text_handler.start instead. Confirm before removing.
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


def extract_text_link_entities(message) -> list[tuple[str, str]]:
    """Telegram lets a message show arbitrary text as a link to a
    DIFFERENT url (MessageEntity.TEXT_LINK) - e.g. the message displays
    "https://ababank.com" while actually pointing at a phishing domain,
    or even just "Click here" with no visible URL at all. extract_urls()
    only regexes the visible text, so it's blind to both cases; this
    pulls the real (display_text, url) pairs out via PTB's own
    parse_entities()/parse_caption_entities(), which - unlike a
    hand-rolled text[offset:length] slice - correctly accounts for
    Telegram's UTF-16 entity offsets (a naive slice breaks on messages
    with Khmer or emoji before the link, both common here). A photo or
    document's link lives in caption_entities, not entities, so the
    right parser has to be picked based on which one the message has.
    """
    try:
        parsed = (
            message.parse_entities(types=[MessageEntity.TEXT_LINK])
            if message.text is not None
            else message.parse_caption_entities(types=[MessageEntity.TEXT_LINK])
        )
    except Exception:                          # noqa: BLE001 - never let entity parsing break a scan
        return []
    return [(display, entity.url) for entity, display in parsed.items() if entity.url]


async def handle_url(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # effective_message covers normal messages AND business messages.
    # A link can arrive as plain text or as a photo/document caption.
    message = update.effective_message
    if message is None:
        return
    text = message.text or message.caption
    if text is None:
        return

    # Full pipeline: lexical + network trace + DNS/domain age + vector
    # search + LSH. Brand/phish vectors are seeded once per process.
    await ensure_vectors_seeded(context.bot_data)

    # Network tracing can take a few seconds — show progress first
    # (normal chats only; business flow stays invisible).
    is_business = bool(message.business_connection_id)
    status = None if is_business else await message.reply_text("🔍 Checking link...", parse_mode="Markdown")

    hidden_links = extract_text_link_entities(message)
    verdicts = await check_message_full(text, hidden_links)
    if not verdicts:
        if status is not None:
            await status.delete()
        return  # this handler only speaks up when there's actually a link

    await _reply_with_verdicts(update, context, message, verdicts, status, is_business)


async def _reply_with_verdicts(update, context, message, verdicts: list[dict],
                                status, is_business: bool) -> None:
    """Once you have a list of verdicts, the business/private/group reply
    branching is identical regardless of where the link(s) came from."""
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

    # --- Private DM with the bot itself: full breakdown right away, no button. ---
    chat = update.effective_chat
    is_private = chat is not None and chat.type == "private"

    if is_private:
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


# ---------------------------------------------------------------------------
# Business chat automation: ONE unified text+link+file check per message,
# reasoning over everything together (see bot/context_engine.py) instead of
# separate, uncoordinated per-signal checks. Telegram's Business API lets a
# user connect Angket to their own business account so every customer
# message gets checked automatically and privately reported to them.
# ---------------------------------------------------------------------------

def _format_unified_business_text(unified: dict, lang: str = DEFAULT_LANG) -> str:
    """Markdown rendering of an analyze_unified() verdict for the business
    owner-DM notification - same shape as text_handler.py's
    format_unified_response, but Markdown instead of HTML to match every
    other business notification in this file. `lang` here is the OWNER's
    language (see _owner_lang), not the customer's.

    unified["ai_unavailable"] means there's no AI-authored reasons/
    recommendations text to show - see format_unified_response's
    docstring for why this replaces the Key Reasons/What They Can Do
    sections with one fixed, translated notice instead."""
    verdict_icon, verdict_label = verdict_style(unified.get("verdict"), lang)
    risk_icon, risk_label = risk_style(unified.get("risk_percentage"), lang)
    risk_percentage = unified.get("risk_percentage")
    percentage = f"{risk_percentage}%" if risk_percentage is not None else "N/A"

    if unified.get("ai_unavailable"):
        return "\n".join([
            f"{verdict_icon} *{t(lang, 'verdict_label')}: {verdict_label}*",
            f"{risk_icon} *{percentage}  {risk_label.upper()}*",
            "",
            f"⚠️ {t(lang, 'ai_unavailable_notice')}",
            "",
            t(lang, "business_disclaimer"),
        ])

    reason_lines = [
        f"- {r.get('text', '')}{SOURCE_TAGS.get(r.get('source'), '')}"
        for r in (unified.get("key_reasons") or [])
    ] or [f"- {t(lang, 'none_provided')}"]

    lines = [
        f"{verdict_icon} *{t(lang, 'verdict_label')}: {verdict_label}*",
        f"{risk_icon} *{percentage}  {risk_label.upper()}*",
        "",
        f"*{t(lang, 'key_reasons_header')}*",
        "\n".join(reason_lines),
    ]
    recs = unified.get("recommendations") or []
    if recs:
        lines += ["", f"*{t(lang, 'business_what_they_can_do_header')}*", "\n".join(f"- {r}" for r in recs)]
    lines += ["", t(lang, "business_disclaimer")]
    return "\n".join(lines)


async def handle_business_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Unified text+link+file check for Telegram Business chat automation:
    when a customer messages a connected business account, the owner gets
    ONE private notification reasoning over everything found in that
    message together, instead of separate per-signal checks.

    Covers text/caption, links, and attached documents - a business photo
    is handled the same way via its caption (message.text or
    message.caption both fall through to the same `text` variable below).
    There is no image-content analysis (no QR decoding) - out of scope by
    design, see bot.py's group comment.
    """
    message = update.effective_message
    if message is None:
        return

    text = message.text or message.caption or ""
    keyword_result = analyze_text(text)

    # Resolved first (usually a bot_data cache hit, not a real network
    # call) so a revoked/unresolvable connection skips the expensive link
    # trace + file scan below entirely, instead of paying for both and
    # then discarding the result.
    owner_chat_id = await _owner_chat_id(context, message.business_connection_id)
    if owner_chat_id is None:
        return  # can't resolve the owner right now - nothing safe to do

    await ensure_vectors_seeded(context.bot_data)

    hidden_links = extract_text_link_entities(message)
    document = message.document

    async def _check_file() -> dict:
        sha256 = await download_and_hash(context, document.file_id)
        return await scan_vt_hash(sha256)

    # A message can have both a link (in caption/entities) and a file at
    # once - the two checks are fully independent network chains, so run
    # them concurrently instead of paying their latency back-to-back.
    # return_exceptions=True matters here: without it, one check failing
    # (e.g. a file over Telegram's download limit, or a VirusTotal
    # hiccup) would discard an ALREADY-SUCCEEDED link result and crash
    # the whole handler - the owner would learn about neither, even
    # though the link check had already come back clean. Same pattern
    # pipeline.py's analyze_url already uses for its own network/DNS/
    # RDAP/TLS gather.
    tasks = [check_message_full(text, hidden_links)]
    if document is not None:
        tasks.append(_check_file())
    results = await asyncio.gather(*tasks, return_exceptions=True)

    link_verdicts = results[0]
    if isinstance(link_verdicts, Exception):
        logger.exception("Link check failed in business chat", exc_info=link_verdicts)
        link_verdicts = []

    file_verdict = results[1] if document is not None else None
    if isinstance(file_verdict, Exception):
        logger.exception("File check failed in business chat", exc_info=file_verdict)
        file_verdict = None

    if not text and not link_verdicts and file_verdict is None:
        return  # truly nothing to check at all - stay silent

    sender = update.effective_user
    for v in link_verdicts:
        log_url_scan(sender.id if sender else None, v["host"], v["score"], v["level"])

    # The OWNER reads this notification, not the customer who sent the
    # message - translate based on their language preference, not the
    # customer's (see _owner_lang's docstring for why those can differ).
    owner_lang = _owner_lang(context, owner_chat_id)
    unified = await analyze_unified(text, keyword_result, link_verdicts, file_verdict, owner_lang)

    # A link or file is always worth telling the owner about (matches
    # handle_url/handle_file's "report every finding, even 'safe'"
    # convention elsewhere in this project). Pure text with no link or
    # file only bothers the owner if the FULL Gemini reasoning actually
    # flags a concern - gating on the crude local keyword list instead
    # (like this used to) is exactly what silently missed a real "Hi Mom,
    # send $800 now, don't call" family-emergency scam during testing:
    # no keyword match, no link, no file, yet obviously a scam.
    if not link_verdicts and file_verdict is None and unified.get("verdict") == "Not a Scam":
        return

    header = f"{t(owner_lang, 'business_new_activity')}\n\n{_sender_header(sender, message.date)}\n\n"
    body = header + _format_unified_business_text(unified, owner_lang)

    # Reuses the toggle-oriented short/full ticket store with the SAME
    # text in both slots - this notification never renders a "See full
    # details" toggle (only Delete), so there's no distinct short/full
    # content to store; the ticket only needs to exist for the "x"
    # (delete) callback to find something to pop.
    ticket = _stash_business_ticket(context, body, body)
    keyboard = InlineKeyboardMarkup(
        [[InlineKeyboardButton("🗑️ Delete", callback_data=f"u:x:{ticket}")]]
    )

    await context.bot.send_message(
        chat_id=owner_chat_id,
        text=body,
        parse_mode="Markdown",
        disable_web_page_preview=True,
        reply_markup=keyboard,
    )
