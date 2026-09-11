import asyncio
import logging
from html import escape

from telegram import ReplyKeyboardMarkup, Update
from telegram.ext import ContextTypes

from bot.detectors.file.scanner import download_and_hash, scan_file
from bot.detectors.text.online.llm import analyze_text_with_llm
from bot.detectors.text.offline.keyword import analyze_text
from bot.context_engine.context_engine import analyze_unified, _message_is_only_links
from bot.response.translate import DEFAULT_LANG
from bot.response.buttons import BUTTONS, key_for_label, label, t
from bot.detectors.url.offline.vectors import ensure_seeded as ensure_vectors_seeded
from bot.handlers.url_handler import extract_text_link_entities
from bot.storage import subscription
from bot.detectors.url.pipeline import check_message_full
from bot.response.verdict_style import SECTION_DIVIDER, SOURCE_TAGS, defang_domains, risk_style, scan_type_label, summary_sentence, verdict_style
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


def get_user_lang(context: ContextTypes.DEFAULT_TYPE) -> str:
    return str(context.user_data.get("lang", DEFAULT_LANG))


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
    lang = get_user_lang(context)
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
    context.user_data["lang"] = lang


def _format_list(items: list, prefix: str, lang: str = DEFAULT_LANG) -> str:
    if not items:
        return f"{prefix} {t(lang, 'none_provided')}"
    # defang_domains AFTER escape() - see that function's own docstring
    # for why this order matters (domain characters survive escaping
    # unchanged, so matching post-escape is safe; matching first and
    # escaping after would escape away the <code> tags this adds).
    return "\n".join(f"{prefix} {defang_domains(escape(str(item)))}" for item in items)


def format_analysis_response(llm_result: dict, keyword_result: dict) -> str:
    """Group-chat reply - deliberately always English (lang=DEFAULT_LANG),
    unlike format_unified_response below. Group chat's language wiring
    and Gemini call are both out of scope for translation for now (see
    bot.py's TEXT_FILTER) - this function's signature is otherwise identical to
    format_unified_response on purpose, so it stays that way on purpose,
    not by oversight. TYPE is always "text" here - this path never
    reasons over links/files itself (see handle_text's own docstring:
    a group-chat link gets its own separate reply from handle_url)."""
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
        f"{SECTION_DIVIDER}\n{t(lang, 'verdict_disclaimer')}",
    ]

    if keyword_result["suspicious"]:
        matches = escape(", ".join(keyword_result["matches"]))
        lines.insert(3, f"⚠️ <b>{t(lang, 'keyword_match_label')}:</b> <code>{matches}</code>")

    return "\n\n".join(lines)


def format_unified_response(
    unified: dict, keyword_result: dict, lang: str = DEFAULT_LANG,
    has_link: bool = False, has_file: bool = False, has_text: bool = True,
    evidence_degraded: bool = False,
) -> str:
    """Same visual shape as format_analysis_response, but key_reasons are
    {text, source} objects (context_engine.py's schema) instead of plain
    strings, so a reason that came from checking a link can be tagged 🔗
    - the "why" for a verdict a link-only or text-only check couldn't
    have produced on its own.

    Unlike format_analysis_response, this one IS lang-aware: the fixed
    labels/headers come from bot/response/translate/, and the dynamic
    key_reasons/recommendations text is expected to already be in the target
    language (analyze_unified asks Gemini to respond in it directly -
    see context_engine.py).

    has_link/has_file/has_text feed the "📁 TYPE:" line - the caller
    already knows exactly what was actually checked (link_verdicts,
    whether a document was attached, whether the message was more than
    just a bare pasted link), so it's computed there rather than
    guessed back out of the `unified` verdict dict, which carries no
    such bookkeeping itself.

    unified["ai_unavailable"] (set by context_engine.py's
    _grounded_fallback) is internal/log-only now - direct user spec
    (2026-09-11): a degraded (no-AI) reply shows its own real
    key_reasons/recommendations exactly like any other verdict, not a
    generic "AI reasoning was unavailable" admission. _grounded_fallback
    already computes real reasons from offline evidence (keyword
    matches, scam-pattern similarity, link/file findings) and its own
    verdict-appropriate recommendations - nothing special to render here.

    evidence_degraded: True when any link's vector-similarity search
    (Supabase) failed AND the check ended up too thin without it to be
    confident (see pipeline.py's analyze_url - not raised on every
    Supabase blip, only when it could plausibly have mattered) - appends
    one small fixed notice near the end, additive rather than replacing
    the real content."""
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

    reason_items = unified.get("key_reasons") or []
    if reason_items:
        reason_lines = []
        for r in reason_items:
            text, source = (r.get("text", ""), r.get("source")) if isinstance(r, dict) else (str(r), None)
            tag = SOURCE_TAGS.get(source, "")
            reason_lines.append(f"• {defang_domains(escape(text))}{tag}")
        reasons_block = "\n".join(reason_lines)
    else:
        reasons_block = f"• {t(lang, 'none_provided')}"

    lines = [
        header,
        f"{risk_block}\n\n"
        f"🔍 <b>{t(lang, 'key_reasons_header')}</b>\n{reasons_block}",
        f"💡 <b>{t(lang, 'what_to_do_header')}</b>\n"
        f"{_format_list(unified.get('recommendations', []), '✓', lang)}",
        f"{SECTION_DIVIDER}\n{t(lang, 'verdict_disclaimer')}",
    ]

    if keyword_result["suspicious"]:
        matches = escape(", ".join(keyword_result["matches"]))
        lines.insert(3, f"⚠️ <b>{t(lang, 'keyword_match_label')}:</b> <code>{matches}</code>")

    if evidence_degraded:
        lines.insert(-1, f"⚠️ {escape(t(lang, 'evidence_degraded_notice'))}")

    return "\n\n".join(lines)


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
    lang = get_user_lang(context)
    canonical_key = key_for_label(text)
    main_menu_keyboard = MAIN_MENU_KEYBOARDS.get(lang, MAIN_MENU_KEYBOARD)

    if canonical_key == "switch_language":
        await message.reply_text(
            t(lang, "switch_language"),
            parse_mode="HTML",
            reply_markup=get_language_keyboard(lang),
        )
        return

    if canonical_key in {"lang_en", "lang_km"}:
        lang = "en" if canonical_key == "lang_en" else "km"
        context.user_data["lang"] = lang
        await update.message.reply_text(
            t(lang, "language_set"),
            parse_mode="HTML",
            reply_markup=MAIN_MENU_KEYBOARDS.get(lang, MAIN_MENU_KEYBOARD),
        )
        return

    if canonical_key in ("back", "menu") or text.upper() == BTN_MENU:
        await update.message.reply_text(
            t(lang, "menu_title"),
            parse_mode="HTML",
            reply_markup=main_menu_keyboard,
        )
        return

    if canonical_key == "usage":
        # Real daily-quota numbers, not a static blurb - subscription.
        # usage_summary() already existed (unit-tested) but was never
        # actually wired into a real reply until now.
        usage_user_id = update.effective_user.id if update.effective_user else None
        if usage_user_id is not None:
            summary = subscription.usage_summary(usage_user_id)
            await update.message.reply_text(
                t(lang, "usage").format(
                    files_used=summary["files_used"], files_limit=summary["files_limit"],
                    links_used=summary["links_messages_used"], links_limit=summary["links_messages_limit"],
                    tokens_used=summary["tokens_used"], tokens_limit=summary["tokens_limit"],
                ),
                parse_mode="HTML",
                reply_markup=main_menu_keyboard,
            )
        return

    if canonical_key in _MENU_RESPONSE_KEYS:
        await update.message.reply_text(
            t(lang, canonical_key),
            parse_mode="HTML",
            reply_markup=main_menu_keyboard,
        )
        return

    user_id = update.effective_user.id if update.effective_user else None
    if user_id is not None and not subscription.can_scan_link_or_message(user_id):
        await message.reply_text(
            t(lang, "daily_scan_limit_reached").format(limit=subscription.FREEMIUM_DAILY_LINKS_MESSAGES),
            reply_markup=main_menu_keyboard,
        )
        return

    keyword_result = analyze_text(text)

    # Plain private DM: reason over text AND any link together in one
    # Gemini call, instead of the link-only verdict a private-chat link
    # used to fall back to. See bot/context_engine/context_engine.py for why this
    # exists - a text-only scam that includes ANY link, even a
    # lexically clean one, used to lose all of its text reasoning here.
    # Business chat never reaches this function at all (route.py's
    # TEXT_FILTER excludes it) - it's fully owned by
    # handlers/url_handler.handle_business_message, whose
    # owner-DM reply visibility works very differently from a normal
    # chat reply.
    chat = update.effective_chat
    is_plain_private = chat is not None and chat.type == "private"

    if is_plain_private:
        await ensure_vectors_seeded(context.bot_data)

        # A private-chat document WITH a caption (e.g. "please open this
        # invoice, urgent") used to be invisible to this unified check -
        # handle_file (bot.py group 0) scans the file on its own VT-only
        # report, with no idea the caption text is urgent/suspicious, and
        # this function had no idea a file was even attached. Checking it
        # here too (VT is 7-day cached, so this rarely re-hits the
        # network) closes that gap without touching handle_file's own
        # reply/Delete-Ignore buttons, which stay exactly as they are.
        document = message.document

        hidden_links = extract_text_link_entities(message)

        # Always shown now - a text-only message (no link, no file) still
        # goes through the same analyze_unified() call (Gemini + bge-m3),
        # which is just as slow as the link/file path; leaving it silent
        # made the bot look unresponsive on exactly that path.
        status = await message.reply_text(t(lang, STATUS_STAGE_KEYS[0]), parse_mode="Markdown")
        animation_task = asyncio.create_task(animate_status(status, lang))

        async def _check_file():
            sha256 = await download_and_hash(context, document.file_id)
            return await scan_file(sha256, document.file_name or "")

        # Concurrent, independent network chains - return_exceptions=True
        # so a file-check failure can't discard an already-succeeded link
        # result (same pattern handle_business_message already uses).
        tasks = [check_message_full(text, hidden_links)]
        if document is not None:
            tasks.append(_check_file())
        results = await asyncio.gather(*tasks, return_exceptions=True)

        link_verdicts = results[0] if not isinstance(results[0], Exception) else []
        file_verdict = None
        if document is not None:
            file_verdict = results[1] if not isinstance(results[1], Exception) else None

        # try/finally so the animation task can never outlive this handler -
        # without it, an exception here (e.g. a "database is locked" SQLite
        # conflict from record_link_or_message_scan) would leave
        # animation_task running forever, editing the status message every
        # 1.5s for the rest of the process with no way to reach it again,
        # and the user would never get a real reply. Same defense-in-depth
        # pattern file_handler.py's handle_file already uses around its own
        # risky awaits.
        try:
            unified = await analyze_unified(text, keyword_result, link_verdicts, file_verdict, lang, user_id)
            reply_text = format_unified_response(
                unified, keyword_result, lang,
                has_link=bool(link_verdicts),
                has_file=document is not None,
                has_text=not _message_is_only_links(text, link_verdicts),
                evidence_degraded=any(v.get("evidence_degraded") for v in link_verdicts),
            )
            if user_id is not None:
                subscription.record_link_or_message_scan(user_id)
        except Exception:                          # noqa: BLE001 - must still stop the animation and reply
            logger.exception("Unified analysis failed for a private-DM message")
            await stop_status_animation(animation_task)
            await status.edit_text(t(lang, "scan_failed"))
            return

        await stop_status_animation(animation_task)

        await status.edit_text(reply_text, parse_mode="HTML", disable_web_page_preview=True)
        return

    # Group/supergroup chat: unchanged text-only reasoning - any link in
    # the message is still checked separately by url_checker's own
    # handle_url flow.
    llm_result = await analyze_text_with_llm(text, user_id)
    if user_id is not None:
        subscription.record_link_or_message_scan(user_id)

    await message.reply_text(
        format_analysis_response(llm_result, keyword_result),
        parse_mode="HTML",
        reply_markup=main_menu_keyboard,
    )