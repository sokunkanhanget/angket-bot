"""
bot/handlers/url_handler.py
=============================
Telegram wiring for URL checking - the third `<feature>_handler.py`
alongside text_handler.py/file_handler.py (was `url_checker/message/
handler.py`, moved so every handler lives in one place, consistently
named). Thin on purpose — the real detection logic lives in
bot/detectors/url/ (see pipeline.py's module docstring for that
package's layout).

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
from datetime import timedelta

from telegram import MessageEntity, Update
from telegram.error import TelegramError
from telegram.ext import ContextTypes

from bot.detectors.file.scanner import download_and_hash, scan_file
from bot.detectors.text.offline.keyword import analyze_text
from bot.context_engine.context_engine import analyze_unified, _message_is_only_links
from bot.config.config import DISPLAY_TIMEZONE_OFFSET_HOURS
from bot.response.translate import DEFAULT_LANG
from bot.response.buttons import t
from bot.detectors.url.pipeline import (
    check_message_full,
    format_verdict_full,
)
from bot.response.verdict_style import DISCLAIMER_SPACER, SOURCE_TAGS, defang_domains, risk_style, scan_type_label, summary_sentence, verdict_style
from bot.response.status_animation import STATUS_STAGE_KEYS, animate_status, stop_status_animation
from bot.storage.scan_log import log_url_scan
from bot.detectors.url.offline.vectors import ensure_seeded as ensure_vectors_seeded
from bot.storage import subscription

logger = logging.getLogger(__name__)

def _full_breakdown_text(verdicts: list[dict], include_evidence: bool = True) -> str:
    return "\n\n---\n\n".join(
        format_verdict_full(v, include_evidence=include_evidence) for v in verdicts
    )


def _sender_header(sender, sent_at, lang: str = DEFAULT_LANG) -> str:
    """👤/🆔/🕒 block for the "New Activity Detected" business notification -
    direct user spec ("From: username (@username)"), matching
    next-gen-test/flow/angket-bot-message.drawio. The Telegram Bot API
    only ever gives message timestamps in UTC (it has no concept of a
    real per-user timezone at all) - see bot/config/config.py's
    DISPLAY_TIMEZONE_OFFSET_HOURS docstring for why this is one
    project-wide offset, not a genuinely per-user one."""
    if sender:
        name = sender.full_name
        if sender.username:
            # Many real users have no @username set at all (confirmed
            # live via the user-registry sandbox test) - only append
            # the handle when Telegram actually gave one, rather than
            # rendering a literal "(@None)".
            name = f"{name} (@{sender.username})"
    else:
        name = "Unknown sender"
    uid = sender.id if sender else "—"
    if sent_at:
        local_dt = sent_at + timedelta(hours=DISPLAY_TIMEZONE_OFFSET_HOURS)
        when = f"{local_dt.strftime('%d %b %Y, %I:%M %p')} (UTC{DISPLAY_TIMEZONE_OFFSET_HOURS:+d})"
    else:
        when = "—"
    return f"👤 `{name}`\n🆔 {uid}\n🕒 {when}"


def _business_header(sender, sent_at, lang: str = DEFAULT_LANG) -> str:
    """"👀 New Activity Detected" banner + sender block + divider, prepended
    above the SAME unified verdict body every other surface renders -
    direct user spec ("use the same format but with added this at the
    top") for Business chat/Live Detect specifically."""
    return f"{t(lang, 'business_new_activity')}\n\n{_sender_header(sender, sent_at, lang)}\n{DISCLAIMER_SPACER}\n"


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

    # Business-chat scans are gated by the Live Detect trial, not the
    # sender's daily quota - the sender there is a CUSTOMER messaging
    # the business, not the subscriber whose plan this is. A normal
    # chat's sender IS the subscriber, so their own daily quota applies.
    sender = update.effective_user
    if not is_business and sender is not None and not subscription.can_scan_link_or_message(sender.id):
        # Inlined rather than importing text_handler.get_user_lang - that
        # module already imports FROM this one (extract_text_link_entities),
        # so the reverse import would be circular.
        lang = str(context.user_data.get("lang", DEFAULT_LANG))
        await message.reply_text(
            t(lang, "daily_scan_limit_reached").format(limit=subscription.FREEMIUM_DAILY_LINKS_MESSAGES)
        )
        return

    # Group chat stays English-only (DEFAULT_LANG), same established
    # scope as format_analysis_response - see bot.py's TEXT_FILTER notes.
    status = None
    animation_task = None
    if not is_business:
        status = await message.reply_text(t(DEFAULT_LANG, STATUS_STAGE_KEYS[0]), parse_mode="Markdown")
        animation_task = asyncio.create_task(animate_status(status, DEFAULT_LANG))

    hidden_links = extract_text_link_entities(message)
    verdicts = await check_message_full(text, hidden_links)

    if animation_task is not None:
        await stop_status_animation(animation_task)

    if not verdicts:
        if status is not None:
            await status.delete()
        return  # this handler only speaks up when there's actually a link

    if not is_business and sender is not None:
        subscription.record_link_or_message_scan(sender.id)

    await _reply_with_verdicts(update, context, message, verdicts, status, is_business)


async def _reply_with_verdicts(update, context, message, verdicts: list[dict],
                                status, is_business: bool) -> None:
    """Once you have a list of verdicts, the business/private/group reply
    branching is identical regardless of where the link(s) came from. No
    buttons anywhere (direct user spec) - every surface just gets the
    full breakdown straight away instead of a short showcase behind a
    "see more"/toggle button, which is what the buttons existed for."""
    sender = update.effective_user
    for v in verdicts:
        log_url_scan(sender.id if sender else None, v["host"], v["score"], v["level"])

    # No Technical Evidence section on any live reply - the spec'd
    # template has no such section, unlike the old private-DM/group-detail
    # split this replaced (private already hid it; group's old "See full
    # details" button was the only place it ever showed).
    full = _full_breakdown_text(verdicts, include_evidence=False)

    if is_business:
        owner_chat_id = await _owner_chat_id(context, message.business_connection_id)
        if owner_chat_id is None:
            return  # can't resolve the owner right now — nothing safe to do

        owner_lang = _owner_lang(context, owner_chat_id)
        body = _business_header(sender, message.date, owner_lang) + full
        await context.bot.send_message(
            chat_id=owner_chat_id,
            text=body,
            parse_mode="Markdown",
            disable_web_page_preview=True,
        )
        return

    await status.edit_text(
        full,
        parse_mode="Markdown",
        disable_web_page_preview=True,  # don't preview a possibly-bad link
    )


def _format_unified_business_text(
    unified: dict, lang: str = DEFAULT_LANG,
    has_link: bool = False, has_file: bool = False, has_text: bool = True,
    evidence_degraded: bool = False,
) -> str:
    """Markdown rendering of an analyze_unified() verdict for the business
    owner-DM notification - SAME VERDICT/TYPE/risk/reasons/what-to-do/
    disclaimer shape as text_handler.py's format_unified_response and
    pipeline.py/file_handler.py's replies, direct user spec that all four
    surfaces read as one consistent product. `lang` here is the OWNER's
    language (see _owner_lang), not the customer's. has_link/has_file/
    has_text feed the "🗁 TYPE:" line, same convention as
    format_unified_response - see that function's docstring.

    unified["ai_unavailable"] is internal/log-only now - see
    format_unified_response's docstring: direct user spec (2026-09-11),
    a degraded (no-AI) reply shows its own real key_reasons/
    recommendations exactly like any other verdict, not a generic
    admission that AI reasoning was unavailable.

    evidence_degraded: see format_unified_response's own docstring -
    same "Supabase failed AND it could plausibly have mattered" gate,
    additive rather than replacing the real content."""
    verdict = unified.get("verdict")
    verdict_icon, verdict_label = verdict_style(verdict, lang)
    risk_icon, risk_label = risk_style(unified.get("risk_percentage"), lang)
    risk_percentage = unified.get("risk_percentage")
    percentage = f"{risk_percentage}%" if risk_percentage is not None else "N/A"
    scan_type = scan_type_label(has_text, has_link, has_file)
    degraded_line = [f"⚠️ {t(lang, 'evidence_degraded_notice')}", ""] if evidence_degraded else []

    reason_lines = [
        f"• {defang_domains(r.get('text', ''), style='markdown')}{SOURCE_TAGS.get(r.get('source'), '')}"
        for r in (unified.get("key_reasons") or [])
    ] or [f"• {t(lang, 'none_provided')}"]
    recs = unified.get("recommendations") or []
    rec_lines = [f"✓ {defang_domains(r, style='markdown')}" for r in recs] or [f"✓ {t(lang, 'none_provided')}"]

    lines = [
        f"{verdict_icon} *{t(lang, 'verdict_label')}: {verdict_label}*",
        f"🗁 *{t(lang, 'type_label')}: {scan_type}*",
        summary_sentence(verdict, risk_percentage, lang),
        "",
        f"{risk_icon} *{percentage}  {risk_label.upper()}*",
        "",
        f"🔍 *{t(lang, 'key_reasons_header')}*",
        "\n".join(reason_lines),
        "",
        f"💡 *{t(lang, 'what_to_do_header')}*",
        "\n".join(rec_lines),
        "",
        *degraded_line,
        DISCLAIMER_SPACER,
        t(lang, "verdict_disclaimer"),
    ]
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

    # Real, confirmed bug: this handler had no way to tell "a customer
    # messaged the business" apart from "the business owner sent/replied
    # to a message in their own connected chat" - EVERY message in the
    # conversation, in either direction, was getting the full unified
    # Gemini check, including the owner's own casual replies ("Working
    # now", "send again"). Confirmed live: this is also what was burning
    # through the Gemini free-tier quota so fast during testing - a
    # short back-and-forth conversation meant several Gemini calls, not
    # one. A private chat's chat_id equals that user's own user_id in
    # Telegram, and owner_chat_id IS exactly the owner's user_id
    # (BusinessConnection.user_chat_id) - so the sender being the owner
    # is a simple, reliable equality check, no separate lookup needed.
    sender = update.effective_user
    if sender is not None and sender.id == owner_chat_id:
        return  # this is the owner's own message/reply - nothing to check

    # Live Detect (this automation) is a 7-day Freemium trial, then
    # gated behind the paid tier. ensure_trial_started is idempotent -
    # only the FIRST business message from a given owner actually starts
    # their clock. NOTE: this notifies the owner on EVERY message once
    # expired, not just once - simple for now, but could get spammy for
    # a business receiving many messages after expiry; worth revisiting
    # if that turns out to be a real annoyance.
    subscription.ensure_trial_started(owner_chat_id)
    if not subscription.live_detect_allowed(owner_chat_id):
        await context.bot.send_message(
            chat_id=owner_chat_id, text=t(_owner_lang(context, owner_chat_id), "live_detect_trial_ended")
        )
        return

    await ensure_vectors_seeded(context.bot_data)

    hidden_links = extract_text_link_entities(message)
    document = message.document

    async def _check_file() -> dict:
        sha256 = await download_and_hash(context, document.file_id)
        return await scan_file(sha256, document.file_name or "")

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

    # `sender` already resolved above (and confirmed not the owner) - no
    # need to re-read update.effective_user a second time.
    for v in link_verdicts:
        log_url_scan(sender.id if sender else None, v["host"], v["score"], v["level"])

    # The OWNER reads this notification, not the customer who sent the
    # message - translate based on their language preference, not the
    # customer's (see _owner_lang's docstring for why those can differ).
    owner_lang = _owner_lang(context, owner_chat_id)
    # sender is a VERIFIED connected customer here (a Business connection,
    # not a spoofable plain chat display name) - safe to let Gemini weigh
    # it as a mitigating signal for a mismatched/redirect domain. See
    # analyze_unified's own docstring for why this is Business-chat-only.
    sender_identity = (
        {"name": sender.full_name, "username": sender.username} if sender else None
    )
    unified = await analyze_unified(
        text, keyword_result, link_verdicts, file_verdict, owner_lang,
        sender_identity=sender_identity,
    )

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

    body = _business_header(sender, message.date, owner_lang) + _format_unified_business_text(
        unified, owner_lang,
        has_link=bool(link_verdicts),
        has_file=document is not None,
        has_text=not _message_is_only_links(text, link_verdicts),
        evidence_degraded=any(v.get("evidence_degraded") for v in link_verdicts),
    )

    # Real, confirmed bug: this had no error handling at all - a
    # Markdown-parsing failure (e.g. an odd number of underscores in a
    # real filename, confirmed live) previously killed the WHOLE
    # notification silently, no matter how correct the underlying verdict
    # was. Every OTHER failure mode in this handler already degrades
    # gracefully (Gemini down, VirusTotal down, a file/link check itself
    # failing) - this is the one place that didn't, despite being the
    # very last step where all of that work could still be thrown away.
    # Retrying once with parse_mode=None (plain text, Telegram does zero
    # entity parsing) turns "the owner never even knew this happened"
    # into "the owner still gets the real verdict, just without bold
    # formatting."
    try:
        await context.bot.send_message(
            chat_id=owner_chat_id,
            text=body,
            parse_mode="Markdown",
            disable_web_page_preview=True,
        )
    except TelegramError:
        logger.exception("Business notification failed to send with Markdown formatting - retrying as plain text")
        try:
            await context.bot.send_message(
                chat_id=owner_chat_id,
                text=body,
                disable_web_page_preview=True,
            )
        except TelegramError:
            logger.exception("Business notification failed even as plain text - giving up for this message")
