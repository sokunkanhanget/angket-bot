"""
bot/handlers/url_handler.py
=============================
Telegram wiring for URL checking - the third `<feature>_handler.py`
alongside text_handler.py/file_handler.py (was `url_checker/message/
handler.py`, moved so every handler lives in one place, consistently
named). Thin on purpose — the real detection logic lives in
bot/detectors/url/ (see pipeline.py's module docstring for that
package's layout).

This file is now entirely Business chat automation ("Live Detect").
Plain private-DM and group-chat link checking live in text_handler.py's
handle_text/handle_check instead (a real link is one of several signals
those unify with Gemini, not a separate reply) - this module's own
standalone group-chat link checker (handle_url, the old "showcase +
deep-link button" flow the paragraph below used to describe) was removed
2026-09-19 once bot.py stopped registering it (group chat has no live/
unprompted scanning at all now, only /check) and nothing else called it.

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

That private DM shows who sent it (full name, id, timestamp) and the
same unified VERDICT/TYPE/KEY REASONS/WHAT TO DO breakdown every other
surface uses - sent immediately as a "Checking..." status, then edited
in place once the real check finishes. No buttons anywhere (direct user
spec, 2026-09-11) - every surface just gets the full breakdown straight
away.

Key detail: we read `update.effective_message` instead of
`update.message`, because business messages arrive on
`update.business_message` — `update.message` is always None for those.
"""

from __future__ import annotations

import asyncio
import logging

from telegram import MessageEntity, Update
from telegram.error import TelegramError
from telegram.ext import ContextTypes

from bot.detectors.file.scanner import download_and_hash, scan_file
from bot.detectors.text.offline.keyword import analyze_text
from bot.context_engine.context_engine import analyze_unified, _message_is_only_links
from bot.response.translate import DEFAULT_LANG
from bot.response.buttons import t
from bot.detectors.url.pipeline import check_message_full
from bot.response.verdict_style import DISCLAIMER_SPACER, SOURCE_TAGS, defang_domains, format_local_datetime, risk_style, scan_type_label, summary_sentence, trusted_link_notice, verdict_style
from bot.response.status_animation import STATUS_STAGE_KEYS, animate_status, stop_status_animation
from bot.storage.scan_log import log_url_scan
from bot.detectors.url.offline.vectors import ensure_seeded as ensure_vectors_seeded
from bot.storage import health_alerts, subscription

logger = logging.getLogger(__name__)


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
    when = format_local_datetime(sent_at) if sent_at else "—"
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
    except TelegramError as error:
        # Real gap fixed 2026-09-19 (direct user spec: "don't make Live
        # Detect fail silently") - this used to just `return None` with
        # zero logging, meaning a customer's message could vanish with
        # no trace anywhere if the connection lookup ever failed (e.g.
        # transient Telegram API hiccup, or a revoked-but-not-yet-synced
        # connection). Same record_failure/maybe_alert pattern already
        # used for Gemini/VirusTotal/Supabase - surfaces to ADMIN_CHAT_ID
        # after repeated failures instead of vanishing into the void.
        logger.exception("Failed to resolve business connection %s to an owner chat id", business_connection_id)
        health_alerts.record_failure("Business chat owner lookup", str(error))
        await health_alerts.maybe_alert("Business chat owner lookup", str(error))
        return None
    cache[business_connection_id] = conn.user_chat_id
    return conn.user_chat_id


async def _owner_lang(context: ContextTypes.DEFAULT_TYPE, owner_chat_id: int) -> str:
    """The business-owner-DM notification is read only by the OWNER, never
    the customer - so it must translate based on the OWNER's language
    preference, not whatever context.user_data the current (customer's)
    update happens to carry. A private chat_id equals that user's own
    user_id in Telegram, and PTB keeps one shared user_data store keyed
    by user_id across every chat that user touches (Application.user_data,
    a read-only Mapping - not context.user_data, which is scoped to the
    CURRENT update's effective_user). If the owner has run /start or
    switched language in their own private chat with the bot SINCE this
    process started, it's already sitting under this same key - cheap,
    no DB hit. Falls through to the same durable Supabase lookup
    text_handler.get_user_lang uses (2026-09-22) on a cache miss - e.g.
    right after a Render restart, before the owner's own next private
    message would otherwise have repopulated this in-memory-only store -
    same bug class that migration fixed, just a second call site."""
    owner_data = context.application.user_data.get(owner_chat_id) or {}
    cached = owner_data.get("lang")
    if cached is not None:
        return cached
    stored = await subscription.get_stored_lang(owner_chat_id)
    return stored or DEFAULT_LANG


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


async def _scan_attached_file(context: ContextTypes.DEFAULT_TYPE, document) -> dict:
    """download_and_hash -> scan_file for one attached document. A plain
    top-level function rather than a closure over context/document (as it
    used to be, nested inside handle_business_message) - no reuse reason
    to capture instead of pass explicitly, and it's used exactly once.
    Same fix as text_handler.py's own former _check_file closure this
    session - kept as a separate copy here rather than shared, since
    text_handler.py already imports extract_text_link_entities FROM this
    module, so importing back would be circular."""
    sha256 = await download_and_hash(context, document.file_id)
    return await scan_file(sha256, document.file_name or "")


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


def _format_business_reasons(reason_items: list, lang: str) -> list[str]:
    """{text, source}-shaped reasons into the bullet-list lines
    _format_unified_business_text renders - Markdown-styled twin of
    text_handler.py's _format_key_reasons (kept local, not shared - see
    _scan_attached_file's own note on why this file can't import from
    text_handler.py)."""
    lines = [
        f"• {defang_domains(r.get('text', ''), style='markdown')}{SOURCE_TAGS.get(r.get('source'), '')}"
        for r in reason_items
    ]
    return lines or [f"• {t(lang, 'none_provided')}"]


def _format_business_recommendations(recs: list[str], lang: str) -> list[str]:
    lines = [f"✓ {defang_domains(r, style='markdown')}" for r in recs]
    return lines or [f"✓ {t(lang, 'none_provided')}"]


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
    has_text feed the "📁 TYPE:" line, same convention as
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

    reason_lines = _format_business_reasons(unified.get("key_reasons") or [], lang)
    rec_lines = _format_business_recommendations(unified.get("recommendations") or [], lang)

    lines = [
        f"{verdict_icon} *{t(lang, 'verdict_label')}: {verdict_label}*",
        f"📁 *{t(lang, 'type_label')}: {scan_type}*",
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
        t(lang, "verdict_disclaimer"),
    ]
    return "\n".join(lines)


def _is_owner_own_message(sender, owner_chat_id: int) -> bool:
    """Real, confirmed bug: this handler had no way to tell "a customer
    messaged the business" apart from "the business owner sent/replied
    to a message in their own connected chat" - EVERY message in the
    conversation, in either direction, was getting the full unified
    Gemini check, including the owner's own casual replies ("Working
    now", "send again"). Confirmed live: this is also what was burning
    through the Gemini free-tier quota so fast during testing - a
    short back-and-forth conversation meant several Gemini calls, not
    one. A private chat's chat_id equals that user's own user_id in
    Telegram, and owner_chat_id IS exactly the owner's user_id
    (BusinessConnection.user_chat_id) - so the sender being the owner
    is a simple, reliable equality check, no separate lookup needed."""
    return sender is not None and sender.id == owner_chat_id


async def _gate_live_detect(context: ContextTypes.DEFAULT_TYPE, owner_chat_id: int) -> bool:
    """True if Live Detect is expired/not started and the caller must
    stop here. Live Detect (this automation) is a 7-day Freemium trial,
    then gated behind the paid tier. ensure_trial_started is idempotent -
    only the FIRST business message from a given owner actually starts
    their clock. Direct user spec (2026-09-15): tell the owner ONCE
    that Live Detect stopped working, not on every customer message
    that arrives afterward - previously every message after expiry
    re-sent the same notice, which would get spammy for a business
    receiving many messages. See should_notify_live_detect_ended's own
    docstring for why nothing resets this flag today."""
    await subscription.ensure_trial_started(owner_chat_id)
    if await subscription.live_detect_allowed(owner_chat_id):
        return False
    if await subscription.should_notify_live_detect_ended(owner_chat_id):
        await context.bot.send_message(
            chat_id=owner_chat_id, text=t(await _owner_lang(context, owner_chat_id), "live_detect_trial_ended"),
            parse_mode="HTML",
        )
    return True


async def _send_business_status(context: ContextTypes.DEFAULT_TYPE, owner_chat_id: int, sender,
                                 message_date, owner_lang: str):
    """(status, animation_task, header), or (None, None, None) on send
    failure. Immediate two-stage notification (2026-09-14, direct user
    spec): the full unified check (link trace + file scan + Gemini) can
    take several real seconds, and the owner used to get NOTHING at all
    until it finished - no idea a message even arrived, let alone from
    whom. Send the "New Activity Detected" + sender header (WHO it's
    from) immediately with a status animation ("Checking...") right
    where the verdict will land, then edit this SAME message into the
    final verdict once ready - same animate_status/stop_status_animation
    pattern every other scan surface (text/link/file) already uses, just
    with the header as a `prefix` instead of starting bare."""
    header = _business_header(sender, message_date, owner_lang)
    try:
        status = await context.bot.send_message(
            chat_id=owner_chat_id,
            text=f"{header}{t(owner_lang, STATUS_STAGE_KEYS[0])}",
            parse_mode="Markdown",
        )
    except TelegramError as error:
        # 2026-09-19 (direct user spec: "don't make Live Detect fail
        # silently"): logged already, but never surfaced past this
        # handler's own log line - the most likely real cause is the
        # owner never having started a private chat with the bot
        # (Telegram refuses "bot can't initiate conversation" for a DM
        # the user hasn't opened first), which would then fail this way
        # for EVERY future customer message with nothing anywhere to
        # notice it. Same record_failure/maybe_alert pattern as every
        # other backend failure in this project - surfaces to
        # ADMIN_CHAT_ID after repeated failures instead of vanishing.
        logger.exception("Business chat status notification failed to send")
        health_alerts.record_failure("Business chat owner DM", str(error))
        await health_alerts.maybe_alert("Business chat owner DM", str(error))
        return None, None, None  # can't even show progress right now - nothing safe to do
    animation_task = asyncio.create_task(animate_status(status, owner_lang, prefix=header))
    return status, animation_task, header


async def _gather_business_check_verdicts(text: str, hidden_links: list, document,
                                           context: ContextTypes.DEFAULT_TYPE, sender):
    """(link_verdicts, file_verdict). A message can have both a link (in
    caption/entities) and a file at once - the two checks are fully
    independent network chains, so run them concurrently instead of
    paying their latency back-to-back. return_exceptions=True matters
    here: without it, one check failing (e.g. a file over Telegram's
    download limit, or a VirusTotal hiccup) would discard an
    ALREADY-SUCCEEDED link result and crash the whole handler - the
    owner would learn about neither, even though the link check had
    already come back clean. Same pattern pipeline.py's analyze_url
    already uses for its own network/DNS/RDAP/TLS gather.

    Kept as a LOCAL helper rather than reusing text_handler.py's own
    _gather_check_verdicts (same job, different file): this one logs
    each failure with logger.exception, which that shared helper does
    not - reusing it would silently drop that logging, so this is a
    deliberate choice, not an oversight."""
    tasks = [check_message_full(text, hidden_links)]
    if document is not None:
        tasks.append(_scan_attached_file(context, document))
    results = await asyncio.gather(*tasks, return_exceptions=True)

    link_verdicts = results[0]
    if isinstance(link_verdicts, Exception):
        logger.exception("Link check failed in business chat", exc_info=link_verdicts)
        link_verdicts = []

    file_verdict = results[1] if document is not None else None
    if isinstance(file_verdict, Exception):
        logger.exception("File check failed in business chat", exc_info=file_verdict)
        file_verdict = None

    # `sender` is already resolved/confirmed-not-the-owner by the caller.
    for v in link_verdicts:
        await asyncio.to_thread(
            log_url_scan, sender.id if sender else None, v["host"], v["score"], v["level"]
        )
    return link_verdicts, file_verdict


async def _send_with_markdown_fallback(status, body: str) -> None:
    """Real, confirmed bug: this had no error handling at all - a
    Markdown-parsing failure (e.g. an odd number of underscores in a
    real filename, confirmed live) previously killed the WHOLE
    notification silently, no matter how correct the underlying verdict
    was. Every OTHER failure mode in handle_business_message already
    degrades gracefully (Gemini down, VirusTotal down, a file/link check
    itself failing) - this is the one place that didn't, despite being
    the very last step where all of that work could still be thrown
    away. Retrying once with parse_mode=None (plain text, Telegram does
    zero entity parsing) turns "the owner never even knew this happened"
    into "the owner still gets the real verdict, just without bold
    formatting."."""
    try:
        await status.edit_text(body, parse_mode="Markdown", disable_web_page_preview=True)
    except TelegramError:
        logger.exception("Business notification failed to send with Markdown formatting - retrying as plain text")
        try:
            await status.edit_text(body, disable_web_page_preview=True)
        except TelegramError:
            logger.exception("Business notification failed even as plain text - giving up for this message")


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

    sender = update.effective_user
    if _is_owner_own_message(sender, owner_chat_id):
        return  # this is the owner's own message/reply - nothing to check

    if await _gate_live_detect(context, owner_chat_id):
        return

    # The OWNER reads this notification, not the customer who sent the
    # message - translate based on their language preference, not the
    # customer's (see _owner_lang's docstring for why those can differ).
    owner_lang = await _owner_lang(context, owner_chat_id)

    status, animation_task, header = await _send_business_status(context, owner_chat_id, sender, message.date, owner_lang)
    if status is None:
        return

    try:
        await ensure_vectors_seeded(context.bot_data)

        hidden_links = extract_text_link_entities(message)
        document = message.document

        link_verdicts, file_verdict = await _gather_business_check_verdicts(
            text, hidden_links, document, context, sender,
        )

        if not text and not link_verdicts and file_verdict is None:
            # Truly nothing to check at all - stay silent, same as
            # before, but now a real status message exists and must be
            # cleaned up instead of left showing "Checking..." forever.
            await stop_status_animation(animation_task)
            await status.delete()
            return

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

    except Exception:                          # noqa: BLE001 - must still stop the animation and tell the owner something
        logger.exception("Business chat unified analysis failed")
        await stop_status_animation(animation_task)
        try:
            await status.edit_text(f"{header}{t(owner_lang, 'scan_failed')}", parse_mode="Markdown")
        except TelegramError:
            pass
        return

    await stop_status_animation(animation_task)

    trusted_host = unified.get("trusted_link_notice_host")
    if trusted_host:
        # Real bug, found by code review (2026-09-16): the trusted-link-
        # notice change was wired into text_handler.py's two callers and
        # this file's own group-chat _reply_with_verdicts, but never
        # into THIS handler - a customer sending a business owner
        # nothing but a bare trusted-brand link still got the full
        # VERDICT/KEY REASONS/WHAT TO DO template. analyze_unified's
        # _trusted_bare_link_verdict short-circuit fires unconditionally
        # regardless of caller, so this path needed the same check as
        # the other three, just kept behind the real header (who it's
        # from, when) rather than dropping that context.
        body = header + trusted_link_notice(trusted_host, owner_lang, style="markdown")
    else:
        body = header + _format_unified_business_text(
            unified, owner_lang,
            has_link=bool(link_verdicts),
            has_file=document is not None,
            has_text=not _message_is_only_links(text, link_verdicts),
            evidence_degraded=any(v.get("evidence_degraded") for v in link_verdicts),
        )

    await _send_with_markdown_fallback(status, body)
