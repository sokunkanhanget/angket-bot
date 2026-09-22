import asyncio
import logging
from html import escape

from telegram import Chat, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardMarkup, Update
from telegram.error import TelegramError
from telegram.ext import ContextTypes

from bot.config.config import WEBSITE_URL
from bot.detectors.file.scanner import download_and_hash, scan_file
from bot.detectors.text.offline.keyword import analyze_text
from bot.context_engine.context_engine import analyze_unified, _message_is_only_links
from bot.response.translate import DEFAULT_LANG
from bot.response.buttons import BUTTONS, key_for_label, label, t
from bot.detectors.url.offline.vectors import ensure_seeded as ensure_vectors_seeded
from bot.handlers.url_handler import extract_text_link_entities
from bot.storage import subscription
from bot.detectors.url.pipeline import bare_trusted_link, check_message_full
from bot.response.verdict_style import DISCLAIMER_SPACER, SOURCE_TAGS, defang_domains, risk_style, scan_type_label, summary_sentence, trusted_link_notice, verdict_style
from bot.response.status_animation import STATUS_STAGE_KEYS, animate_status, stop_status_animation

logger = logging.getLogger(__name__)

BTN_MENU = "MENU"

# Menu items shown on the main menu, in canonical-key form (excludes "menu" itself).
# "Safety Tips" removed per teammate's call (2026-09-10) - was an
# unused/low-traffic menu item, not a bug fix.
_MAIN_MENU_KEYS = [
    ["switch_language", "how_to_use"],
    ["usage", "policy"],
    ["help", "subscription"],
]

# "usage" is deliberately NOT here - unlike every other menu item, its
# reply is dynamic (real daily-quota numbers from subscription.py), not
# a static translated string t() can render on its own. See its own
# branch in handle_text below.
_MENU_RESPONSE_KEYS = {"how_to_use", "policy", "help", "subscription"}

COMMAND_KEYS = {
    "language": "switch_language",
    "howto": "how_to_use",
    "usage": "usage",
    "policy": "policy",
    "subscription": "subscription",
}

TRIGGER_MENU_KEYBOARD = ReplyKeyboardMarkup(
    [[BTN_MENU]],
    resize_keyboard=True,
    one_time_keyboard=True,
)


def get_main_menu_keyboard(lang: str) -> ReplyKeyboardMarkup:
    locale = lang if lang in BUTTONS else DEFAULT_LANG
    return ReplyKeyboardMarkup(
        [[label(locale, key) for key in row] for row in _MAIN_MENU_KEYS],
        resize_keyboard=True,
    )


MAIN_MENU_KEYBOARDS = {locale: get_main_menu_keyboard(locale) for locale in BUTTONS}
MAIN_MENU_KEYBOARD = MAIN_MENU_KEYBOARDS[DEFAULT_LANG]


async def get_user_lang(context: ContextTypes.DEFAULT_TYPE, user_id: int | None) -> str:
    """context.user_data first (cheap, correct for the rest of this
    process's life) - only falls through to a Supabase read on a cache
    miss, i.e. the first message from this user since the last restart
    (context.user_data itself is pure in-memory, see set_user_lang's
    docstring). Writes the DB result back into context.user_data so this
    is a one-time-per-restart cost, not a query on every message.
    user_id=None (no effective_user - shouldn't normally happen for a
    real user message, but some callers guard defensively) skips the
    Supabase lookup entirely and falls back to DEFAULT_LANG, same as a
    genuine cache miss with nothing stored."""
    cached = context.user_data.get("lang")
    if cached is not None:
        return str(cached)
    stored = await subscription.get_stored_lang(user_id) if user_id is not None else None
    lang = stored or DEFAULT_LANG
    context.user_data["lang"] = lang
    return lang


async def set_user_lang(context: ContextTypes.DEFAULT_TYPE, user_id: int, lang: str) -> None:
    """Writes both the in-process cache (context.user_data - still pure
    in-memory, dies on every restart on its own) and the durable Supabase
    copy (user_state.lang), replacing the two inline
    context.user_data["lang"] = lang assignments this used to be
    (2026-09-22) - language preference used to be lost on every restart,
    not just a Render redeploy's filesystem wipe."""
    context.user_data["lang"] = lang
    await subscription.set_stored_lang(user_id, lang)


def get_language_keyboard(lang: str) -> ReplyKeyboardMarkup:
    locale = lang if lang in BUTTONS else DEFAULT_LANG
    return ReplyKeyboardMarkup(
        [
            [label(locale, "lang_en"), label(locale, "lang_km")],
            [label(locale, "back")],
        ],
        resize_keyboard=True,
    )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    lang = await get_user_lang(context, update.effective_user.id)
    await update.message.reply_text(
        "🛡️ <b>Welcome to Angket Bot</b>\n"
        "Your security assistant for checking suspicious content.\n\n"
        "🔍 What can I scan?\n"
        "• 📝 Text messages\n"
        "• 📄 Files\n"
        "• 🔗 URLs & links\n\n"
        "Use the buttons below to explore the menu.\n\n"
        "Let’s keep your digital world safer.",
        parse_mode="HTML",
        reply_markup=MAIN_MENU_KEYBOARDS.get(lang, MAIN_MENU_KEYBOARD),
    )


async def handle_website(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/website - private chat only (registered with _PRIVATE_CHAT_ONLY in
    bot.py). Direct user spec (2026-09-21): a single external-link button
    to the real Angket website (WEBSITE_URL, config.py). A plain URL
    button (InlineKeyboardButton(url=...)), not a Telegram Mini App/
    WebAppInfo - the site is a full marketing/dashboard page, not built
    for Telegram's constrained webview, so it opens in the user's own
    browser instead. Tapping a URL button never round-trips back to the
    bot at all (unlike a callback-data button), so no callback handler
    is needed for this."""
    message = update.effective_message
    if message is None:
        return
    lang = await get_user_lang(context, update.effective_user.id)
    keyboard = InlineKeyboardMarkup([[InlineKeyboardButton(t(lang, "website_button"), url=WEBSITE_URL)]])
    await message.reply_text(t(lang, "website_prompt"), parse_mode="HTML", reply_markup=keyboard)


def _format_list(items: list, prefix: str, lang: str = DEFAULT_LANG) -> str:
    if not items:
        return f"{prefix} {t(lang, 'none_provided')}"
    # defang_domains AFTER escape() - see that function's own docstring
    # for why this order matters (domain characters survive escaping
    # unchanged, so matching post-escape is safe; matching first and
    # escaping after would escape away the <code> tags this adds).
    return "\n".join(f"{prefix} {defang_domains(escape(str(item)))}" for item in items)


def format_analysis_response(llm_result: dict, keyword_result: dict) -> str:
    """The old group-chat text-only reply - deliberately always English
    (lang=DEFAULT_LANG). No production caller as of 2026-09-19: group
    chat has no live/unprompted scanning at all anymore (only /check,
    which reuses format_unified_response's shape via _run_full_check_and_reply,
    not this function) - kept only for its own direct test coverage
    (test_format_analysis_response_*). This function's signature is
    otherwise identical to format_unified_response on purpose. TYPE is
    always "text" here - this path never reasoned over links/files
    itself even when it was live."""
    lang = DEFAULT_LANG
    verdict = llm_result.get("verdict")
    verdict_icon, verdict_label = verdict_style(verdict, lang)
    risk_icon, risk_label = risk_style(llm_result.get("risk_percentage"), lang)
    risk_percentage = llm_result.get("risk_percentage")
    percentage = f"{risk_percentage}%" if risk_percentage is not None else "N/A"

    lines = [
        f"{verdict_icon} <b>{t(lang, 'verdict_label')}: {escape(verdict_label)}</b>\n"
        f"📁 <b>{t(lang, 'type_label')}: {scan_type_label(True, False, False)}</b>\n"
        + summary_sentence(verdict, risk_percentage, lang),
        f"{risk_icon} <b>{percentage}  {risk_label.upper()}</b>\n\n"
        f"🔍 <b>{t(lang, 'key_reasons_header')}</b>\n{_format_list(llm_result.get('key_reasons', []), '•', lang)}",
        f"💡 <b>{t(lang, 'what_to_do_header')}</b>\n"
        f"{_format_list(llm_result.get('recommendations', []), '✓', lang)}",
        f"{DISCLAIMER_SPACER}{t(lang, 'verdict_disclaimer')}",
    ]

    if keyword_result["suspicious"]:
        matches = escape(", ".join(keyword_result["matches"]))
        lines.insert(3, f"⚠️ <b>{t(lang, 'keyword_match_label')}:</b> <code>{matches}</code>")

    return "\n\n".join(lines)


def _format_key_reasons(reason_items: list, lang: str) -> str:
    """{text, source}-shaped reasons (context_engine.py's schema) into the
    same bullet-list shape _format_list renders for plain strings, plus the
    per-source 🔗-style tag. Split out of format_unified_response so that
    function reads as header/reasons/recommendations/disclaimer instead of
    one long body."""
    if not reason_items:
        return f"• {t(lang, 'none_provided')}"
    reason_lines = []
    for r in reason_items:
        text, source = (r.get("text", ""), r.get("source")) if isinstance(r, dict) else (str(r), None)
        tag = SOURCE_TAGS.get(source, "")
        reason_lines.append(f"• {defang_domains(escape(text))}{tag}")
    return "\n".join(reason_lines)


def format_unified_response(
    unified: dict, keyword_result: dict, lang: str = DEFAULT_LANG,
    has_link: bool = False, has_file: bool = False, has_text: bool = True,
    evidence_degraded: bool = False,
) -> str:
    """Same visual shape as format_analysis_response, but key_reasons are
    {text, source} objects (context_engine.py's schema), tagged 🔗 when a
    reason came from a link check. Lang-aware (unlike
    format_analysis_response): dynamic text is already in the target
    language (analyze_unified asks Gemini directly).

    has_link/has_file/has_text feed the "📁 TYPE:" line - computed by the
    caller, not guessed back out of `unified`. evidence_degraded appends
    one small notice near the end when a link's Supabase vector search
    failed and the check ended up too thin without it."""
    verdict = unified.get("verdict")
    verdict_icon, verdict_label = verdict_style(verdict, lang)
    risk_icon, risk_label = risk_style(unified.get("risk_percentage"), lang)
    risk_percentage = unified.get("risk_percentage")
    percentage = f"{risk_percentage}%" if risk_percentage is not None else "N/A"

    header = (
        f"{verdict_icon} <b>{t(lang, 'verdict_label')}: {escape(verdict_label)}</b>\n"
        f"📁 <b>{t(lang, 'type_label')}: {scan_type_label(has_text, has_link, has_file)}</b>\n"
        + summary_sentence(verdict, risk_percentage, lang)
    )
    risk_block = f"{risk_icon} <b>{percentage}  {risk_label.upper()}</b>"

    reasons_block = _format_key_reasons(unified.get("key_reasons") or [], lang)

    lines = [
        header,
        f"{risk_block}\n\n"
        f"🔍 <b>{t(lang, 'key_reasons_header')}</b>\n{reasons_block}",
        f"💡 <b>{t(lang, 'what_to_do_header')}</b>\n"
        f"{_format_list(unified.get('recommendations', []), '✓', lang)}",
        f"{DISCLAIMER_SPACER}{t(lang, 'verdict_disclaimer')}",
    ]

    if keyword_result["suspicious"]:
        matches = escape(", ".join(keyword_result["matches"]))
        lines.insert(3, f"⚠️ <b>{t(lang, 'keyword_match_label')}:</b> <code>{matches}</code>")

    if evidence_degraded:
        lines.insert(-1, f"⚠️ {escape(t(lang, 'evidence_degraded_notice'))}")

    return "\n\n".join(lines)


async def _reply_usage_summary(update: Update, lang: str, main_menu_keyboard: ReplyKeyboardMarkup) -> None:
    """Real daily-quota numbers for the 'usage' menu item, not a static
    blurb - subscription.usage_summary() already existed (unit-tested) but
    was never actually wired into a real reply until now. Split out of
    _try_handle_menu_command to keep that dispatcher's own branches short."""
    usage_user_id = update.effective_user.id if update.effective_user else None
    if usage_user_id is None:
        return
    summary = await subscription.usage_summary(usage_user_id)
    await update.message.reply_text(
        t(lang, "usage").format(
            files_used=summary["files_used"], files_limit=summary["files_limit"],
            links_used=summary["links_messages_used"], links_limit=summary["links_messages_limit"],
            tokens_used=summary["tokens_used"], tokens_limit=summary["tokens_limit"],
        ),
        parse_mode="HTML",
        reply_markup=main_menu_keyboard,
    )


async def _try_handle_menu_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE, message, text: str, lang: str,
    canonical_key: str | None, main_menu_keyboard: ReplyKeyboardMarkup,
) -> bool:
    """Static menu/settings dispatch - switch_language, lang_en/lang_km,
    back/menu, usage, and the plain static _MENU_RESPONSE_KEYS replies.
    True when it already sent a reply (caller should stop there), False to
    fall through to the real scan path. Split out of handle_text - none of
    this touches scan/quota/analyze_unified logic. Also reused by
    handle_command below, which used to duplicate the switch_language and
    static-key-reply branches by hand."""
    if canonical_key == "switch_language":
        await message.reply_text(
            t(lang, "switch_language"),
            parse_mode="HTML",
            reply_markup=get_language_keyboard(lang),
        )
        return True

    if canonical_key in {"lang_en", "lang_km"}:
        lang = "en" if canonical_key == "lang_en" else "km"
        await set_user_lang(context, update.effective_user.id, lang)
        await update.message.reply_text(
            t(lang, "language_set"),
            parse_mode="HTML",
            reply_markup=MAIN_MENU_KEYBOARDS.get(lang, MAIN_MENU_KEYBOARD),
        )
        return True

    if canonical_key in ("back", "menu") or text.upper() == BTN_MENU:
        await update.message.reply_text(
            t(lang, "menu_title"),
            parse_mode="HTML",
            reply_markup=main_menu_keyboard,
        )
        return True

    if canonical_key == "usage":
        await _reply_usage_summary(update, lang, main_menu_keyboard)
        return True

    if canonical_key in _MENU_RESPONSE_KEYS:
        # Group chat only ever reaches "how_to_use"/"policy" here (see
        # bot.py's CommandHandler filter split, 2026-09-19) - switch_
        # language/usage/back/menu buttons don't exist there, so
        # main_menu_keyboard would show buttons that silently do nothing
        # if tapped (handle_text, the button-tap dispatcher, is
        # private-only now too). Suppress it entirely in groups, and swap
        # how_to_use for its group-specific /check-focused variant.
        chat = update.effective_chat
        is_group = chat is not None and chat.type in (Chat.GROUP, Chat.SUPERGROUP)
        key = "how_to_use_group" if (is_group and canonical_key == "how_to_use") else canonical_key
        await update.message.reply_text(
            t(lang, key),
            parse_mode="HTML",
            reply_markup=None if is_group else main_menu_keyboard,
        )
        return True

    return False


async def _check_quota_gate(message, lang: str, user_id: int | None, trusted_shape: bool,
                             reply_markup=None) -> bool:
    """True if the sender is over today's limit and must be turned away
    here. Shared gate/notify-once logic, previously duplicated between
    handle_text's private-DM branch and handle_check - those two only
    ever differed in lang, plus whether a main-menu keyboard is attached
    to the notice."""
    if user_id is None or trusted_shape or await subscription.can_scan_link_or_message(user_id):
        return False
    # Direct user spec (2026-09-15): tell them once, not on every
    # message they send while still over today's limit - see
    # should_notify_link_limit's own docstring.
    if await subscription.should_notify_link_limit(user_id):
        await message.reply_text(
            t(lang, "daily_scan_limit_reached").format(
                limit=subscription.FREEMIUM_DAILY_LINKS_MESSAGES,
                reset_time=subscription.reset_time_display(),
            ),
            reply_markup=reply_markup,
            parse_mode="HTML",
        )
    return True


async def _scan_attached_file(context: ContextTypes.DEFAULT_TYPE, document) -> dict:
    """download_and_hash -> scan_file for one attached document. A plain
    top-level function rather than a closure over context/document (as it
    used to be, nested inside _run_full_check_and_reply) - no reuse reason
    to capture instead of pass explicitly, and it's used exactly once."""
    sha256 = await download_and_hash(context, document.file_id)
    return await scan_file(sha256, document.file_name or "")


async def _gather_check_verdicts(text: str, hidden_links: list, document, context: ContextTypes.DEFAULT_TYPE):
    """check_message_full (+ file scan if attached), run concurrently -
    return_exceptions=True so a file-check failure can't discard an
    already-succeeded link result. Split out of _run_full_check_and_reply."""
    tasks = [check_message_full(text, hidden_links)]
    if document is not None:
        tasks.append(_scan_attached_file(context, document))
    results = await asyncio.gather(*tasks, return_exceptions=True)

    link_verdicts = results[0] if not isinstance(results[0], Exception) else []
    file_verdict = None
    if document is not None:
        file_verdict = results[1] if not isinstance(results[1], Exception) else None
    return link_verdicts, file_verdict


def _build_reply_text(unified: dict, keyword_result: dict, lang: str, has_text_fn, link_verdicts: list, document):
    """(reply_text, trusted_host) - the short trusted-link notice or the
    full VERDICT/KEY REASONS/WHAT TO DO template. Split out of
    _run_full_check_and_reply. Direct user spec: a bare trusted-brand
    link gets the short notice instead - see verdict_style.trusted_link_notice."""
    trusted_host = unified.get("trusted_link_notice_host")
    if trusted_host:
        return trusted_link_notice(trusted_host, lang, style="html"), trusted_host
    reply_text = format_unified_response(
        unified, keyword_result, lang,
        has_link=bool(link_verdicts),
        has_file=document is not None,
        has_text=has_text_fn(link_verdicts),
        evidence_degraded=any(v.get("evidence_degraded") for v in link_verdicts),
    )
    return reply_text, trusted_host


class _DMReplyTarget:
    """Minimal message.reply_text-shaped shim so _send_check_status can
    target an arbitrary chat_id - specifically, a group /check caller's
    OWN private chat with the bot, rather than replying in the group it
    was typed in (direct user spec, 2026-09-19: keep the group clean,
    DM the invoker the verdict privately). Only reply_text is ever
    called on this - the real telegram.Message that returns from
    send_message already has its own genuine edit_text, which
    _run_full_check_and_reply calls directly on THAT, never on this
    shim itself."""
    def __init__(self, bot, chat_id: int):
        self._bot = bot
        self._chat_id = chat_id

    async def reply_text(self, text, **kwargs):
        return await self._bot.send_message(chat_id=self._chat_id, text=text, **kwargs)


async def _send_check_status(message, lang: str):
    """(status, animation_task) - the "Checking..." status message + its
    live animation. Split out of _run_full_check_and_reply so a caller
    that needs retry/fallback delivery logic (handle_check's DM-first,
    fall-back-to-group-on-failure) can retry just this cheap send, not
    the real analysis work below it (Gemini/link trace - genuinely
    expensive, must never run twice for one /check)."""
    status = await message.reply_text(t(lang, STATUS_STAGE_KEYS[0]), parse_mode="Markdown")
    animation_task = asyncio.create_task(animate_status(status, lang))
    return status, animation_task


async def _run_full_check_and_reply(
    status, animation_task, context: ContextTypes.DEFAULT_TYPE, text: str, hidden_links: list,
    document, keyword_result: dict, lang: str, user_id: int | None, trusted_shape: bool,
    has_text_fn, log_context: str,
) -> None:
    """check_message_full (+ file scan if attached) -> analyze_unified ->
    build the reply -> charge quota -> edit the status message. Shared body
    of handle_text's private-DM branch and handle_check - the two only
    differed in lang, how has_text is computed (has_text_fn - it needs
    link_verdicts, not known until after the real check runs), plus the
    log message on failure.

    Takes an ALREADY-SENT status + its already-started animation_task
    (see _send_check_status) rather than creating them itself, as of
    2026-09-19 - this is what lets handle_check retry/redirect delivery
    of that first message without re-running the real check twice."""
    await ensure_vectors_seeded(context.bot_data)

    link_verdicts, file_verdict = await _gather_check_verdicts(text, hidden_links, document, context)

    # try/finally-equivalent (except/re-stop) so the animation task can
    # never outlive this handler.
    try:
        unified = await analyze_unified(text, keyword_result, link_verdicts, file_verdict, lang, user_id)
        reply_text, trusted_host = _build_reply_text(unified, keyword_result, lang, has_text_fn, link_verdicts, document)
        # trusted_host (deduped-verdict-based) can disagree with
        # trusted_shape (raw-URL-count-based) - e.g. "facebook.com
        # facebook.com" makes trusted_shape False but trusted_host truthy.
        # Charging only when both agree keeps the charge from ever
        # diverging from what the pre-check gate already committed to.
        if user_id is not None and not (trusted_shape and trusted_host):
            await subscription.record_link_or_message_scan(user_id)
    except Exception:                          # noqa: BLE001 - must still stop the animation and reply
        logger.exception("Unified analysis failed for %s", log_context)
        await stop_status_animation(animation_task)
        await status.edit_text(t(lang, "scan_failed"))
        return

    await stop_status_animation(animation_task)
    await status.edit_text(reply_text, parse_mode="HTML", disable_web_page_preview=True)


def _private_dm_scan_shape(update: Update, message, text: str):
    """is_plain_private, document, hidden_links, trusted_shape for
    handle_text's real-scan path - split out to keep handle_text itself
    to orchestration only.

    Business/GROUP/CHANNEL chat never reach handle_text (bot.py's
    TEXT_FILTER excludes all three as of 2026-09-19) - is_plain_private
    is unconditionally True in every real call now, kept mainly as a
    defensive guard rather than a live branch. Business chat is fully
    owned by handlers/url_handler.handle_business_message; group chat's
    only scanning entry point is /check (handle_check).

    trusted_shape is a cheap, no-network shape check (bare_trusted_link):
    only a message that's NOTHING but one link to a verified
    PROTECTED_BRANDS domain qualifies - can never bypass quota on
    arbitrary content. A document attached rules it out too. Confirmed
    again against the real verdict (trusted_host) before the quota
    charge is skipped - see _run_full_check_and_reply."""
    chat = update.effective_chat
    is_plain_private = chat is not None and chat.type == "private"
    document = message.document if is_plain_private else None
    hidden_links = extract_text_link_entities(message) if is_plain_private else []
    trusted_shape = (
        is_plain_private and document is None
        and bare_trusted_link(text, hidden_links) is not None
    )
    return is_plain_private, document, hidden_links, trusted_shape


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if message is None:
        return
    # A caption (photo/document sent with a message) carries the same
    # kind of scam wording plain text does - route.py now sends those
    # here too, so this must not stay blind to message.caption.
    text = message.text or message.caption
    if text is None:
        return
    user_id = update.effective_user.id if update.effective_user else None
    lang = await get_user_lang(context, user_id)
    canonical_key = key_for_label(text)
    main_menu_keyboard = MAIN_MENU_KEYBOARDS.get(lang, MAIN_MENU_KEYBOARD)

    if await _try_handle_menu_command(update, context, message, text, lang, canonical_key, main_menu_keyboard):
        return

    # Plain private DM: reason over text AND any link together in one
    # Gemini call, instead of the link-only verdict a private-chat link
    # used to fall back to - see bot/context_engine/context_engine.py.
    is_plain_private, document, hidden_links, trusted_shape = _private_dm_scan_shape(update, message, text)

    # No status message exists yet at this point in the handler, so
    # "stay silent" on a blocked sender really is silent, not a stray
    # message to clean up.
    if await _check_quota_gate(message, lang, user_id, trusted_shape, main_menu_keyboard):
        return

    keyword_result = analyze_text(text)

    # is_plain_private is unconditionally True here as of 2026-09-19:
    # handle_text is registered only on bot.py's TEXT_FILTER, which now
    # excludes GROUPS (plus the pre-existing CHANNEL/BUSINESS_MESSAGE
    # exclusions) - group chat has no live/unprompted scanning at all
    # anymore, only /check. This dropped the old group-chat "unchanged
    # text-only reasoning via analyze_text_with_llm" branch, which was
    # dead code the moment that filter changed (confirmed by /code-review,
    # 2026-09-19) - format_analysis_response/analyze_text_with_llm are
    # kept (both still have their own direct unit test coverage), just no
    # longer called from here.
    status, animation_task = await _send_check_status(message, lang)
    await _run_full_check_and_reply(
        status, animation_task, context, text, hidden_links, document, keyword_result, lang, user_id, trusted_shape,
        has_text_fn=lambda link_verdicts: not _message_is_only_links(text, link_verdicts),
        log_context="a private-DM message",
    )


async def handle_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/language, /howto, /usage, /policy, /subscription - COMMAND_KEYS only
    ever maps to canonical keys _try_handle_menu_command already handles,
    so delegating to it removes a hand-duplicated copy of that dispatch
    logic."""
    message = update.effective_message
    if message is None or not message.text:
        return

    command_name = message.text.split(maxsplit=1)[0].lstrip("/").split("@", 1)[0].lower()
    canonical_key = COMMAND_KEYS.get(command_name)
    if canonical_key is None:
        return

    lang = await get_user_lang(context, update.effective_user.id if update.effective_user else None)
    main_menu_keyboard = MAIN_MENU_KEYBOARDS.get(lang, MAIN_MENU_KEYBOARD)
    await _try_handle_menu_command(update, context, message, message.text, lang, canonical_key, main_menu_keyboard)


async def handle_check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/check - group/supergroup only (registered with filters.ChatType.GROUPS
    in bot.py). Lets a group member trigger the same private-DM-grade
    pipeline (check_message_full + analyze_unified), as a reply to an
    existing message, or standalone (/check <url or text>) - a deliberate
    per-request call, not a per-message auto-scan. Commands bypass Privacy
    Mode regardless of its BotFather setting, unlike a plain group message
    (see memory: project_group_channel_plan.md).

    English-only (DEFAULT_LANG): group chat has no single "whose language"
    the way private DM's per-user context.user_data gives one."""
    message = update.effective_message
    if message is None:
        return
    user = update.effective_user
    user_id = user.id if user else None

    replied = message.reply_to_message
    if replied is not None:
        target_text = replied.text or replied.caption or ""
        hidden_links = extract_text_link_entities(replied)
        document = replied.document
    elif context.args:
        target_text = " ".join(context.args)
        hidden_links = []
        document = None
    else:
        await message.reply_text(t(DEFAULT_LANG, "check_usage_hint"))
        return

    if not target_text and document is None:
        await message.reply_text(t(DEFAULT_LANG, "check_nothing_to_check"))
        return

    # Same shape/quota-skip pattern as _private_dm_scan_shape's own
    # trusted_shape - see its docstring for why this is safe.
    trusted_shape = document is None and bare_trusted_link(target_text, hidden_links) is not None

    # Shares handle_text's SAME per-user notify-once counter (see
    # _check_quota_gate's docstring).
    if await _check_quota_gate(message, DEFAULT_LANG, user_id, trusted_shape):
        return

    # After the quota gate, not before - an over-quota sender shouldn't
    # trigger a real Supabase call.
    keyword_result = analyze_text(target_text)

    # Direct user spec, 2026-09-19: the verdict goes to the CALLER's own
    # private chat with the bot, not into the group at all - keeps the
    # group clean regardless of reply-vs-standalone /check usage. (Earlier
    # in this same day, before this spec, it threaded onto the original
    # flagged message in-group instead - superseded, not stacked with
    # this.) If the DM can't be delivered (most likely: this user has
    # never started a private chat with the bot, so Telegram refuses
    # "bot can't initiate conversation") retry once, then fall back to
    # replying in the group - direct user spec: never fail silently, and
    # never lose the check entirely just because the DM didn't go through.
    # Only the cheap status-send is retried/redirected here, never the
    # real analysis (Gemini/link trace) - see _send_check_status's own
    # docstring for why re-running that would be wrong.
    fallback_target = replied if replied is not None else message
    status = animation_task = None
    if user_id is not None:
        dm_target = _DMReplyTarget(context.bot, user_id)
        for _attempt in range(2):
            try:
                status, animation_task = await _send_check_status(dm_target, DEFAULT_LANG)
                break
            except TelegramError:
                continue
        else:
            logger.warning(
                "Could not DM /check result to user %s (likely never started "
                "a private chat with the bot) - falling back to a group reply",
                user_id,
            )
    if status is None:
        status, animation_task = await _send_check_status(fallback_target, DEFAULT_LANG)

    await _run_full_check_and_reply(
        status, animation_task, context, target_text, hidden_links, document, keyword_result, DEFAULT_LANG, user_id, trusted_shape,
        has_text_fn=lambda link_verdicts: bool(target_text.strip()),
        log_context="/check",
    )