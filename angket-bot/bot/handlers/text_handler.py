import asyncio
from html import escape

from telegram import ReplyKeyboardMarkup, Update
from telegram.ext import ContextTypes

from bot.analysis.file_scanner import download_and_hash, scan_vt_hash
from bot.analysis.llm_analyzer import analyze_text_with_llm
from bot.analysis.text_analyzer import analyze_text
from bot.context_engine import analyze_unified
from bot.i18n import DEFAULT_LANG, BUTTONS, key_for_label, label, t
from bot.url_checker.features.offline.lexical import URL_REGEX
from bot.url_checker.features.offline.vectors import ensure_seeded as ensure_vectors_seeded
from bot.url_checker.message.handler import extract_text_link_entities, resolve_ticket
from bot.url_checker.pipeline import check_message_full
from bot.verdict_style import SOURCE_TAGS, risk_style, verdict_style

BTN_MENU = "MENU"

# Menu items shown on the main menu, in canonical-key form (excludes "menu" itself).
_MAIN_MENU_KEYS = [
    ["switch_language", "how_to_use"],
    ["safety_tips", "live_scan"],
    ["policy", "help"],
    ["subscription"],
]

_MENU_RESPONSE_KEYS = {"how_to_use", "safety_tips", "live_scan", "policy", "help", "subscription"}

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
    # Deep-link tickets from link-checker showcases arrive here too
    # (t.me/<bot>?start=<ticket>). A valid ticket takes priority over
    # the welcome menu; an expired/unknown one falls through to it.
    if context.args:
        full = resolve_ticket(context, context.args[0])
        if full is not None:
            await update.message.reply_text(
                full,
                parse_mode="Markdown",
                disable_web_page_preview=True,
            )
            return

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
    return "\n".join(f"{prefix} {escape(str(item))}" for item in items)


def _summary(verdict: str | None, risk_percentage: int | None, lang: str = DEFAULT_LANG) -> str:
    if verdict == "Scam":
        if risk_percentage is not None and risk_percentage <= 60:
            return t(lang, "summary_warning_signs")
        return t(lang, "summary_strong_unsafe")
    if verdict == "Not a Scam":
        if risk_percentage is not None and risk_percentage > 30:
            return t(lang, "summary_warning_signs")
        return t(lang, "summary_no_indicators")
    if risk_percentage is not None and risk_percentage > 60:
        return t(lang, "summary_strong_unsafe")
    if risk_percentage is not None and risk_percentage > 30:
        return t(lang, "summary_warning_signs")
    return t(lang, "summary_no_indicators")


def format_analysis_response(llm_result: dict, keyword_result: dict) -> str:
    """Group-chat reply - deliberately always English (lang=DEFAULT_LANG),
    unlike format_unified_response below. Group chat's language wiring
    and Gemini call are both out of scope for translation for now (see
    bot/route.py) - this function's signature is otherwise identical to
    format_unified_response on purpose, so it stays that way on purpose,
    not by oversight."""
    lang = DEFAULT_LANG
    verdict_icon, verdict_label = verdict_style(llm_result.get("verdict"), lang)
    risk_icon, risk_label = risk_style(llm_result.get("risk_percentage"), lang)
    risk_percentage = llm_result.get("risk_percentage")
    percentage = f"{risk_percentage}%" if risk_percentage is not None else "N/A"

    lines = [
        f"{verdict_icon} <b>{t(lang, 'verdict_label')}: {escape(verdict_label)}</b>\n\n"
        + _summary(llm_result.get("verdict"), risk_percentage, lang),
        f"{risk_icon} <b>{percentage}  {risk_label.upper()}</b>\n\n"
        f"🔍 <b>{t(lang, 'key_reasons_header')}</b>\n{_format_list(llm_result.get('key_reasons', []), '•', lang)}",
        f"💡 <b>{t(lang, 'what_to_do_header')}</b>\n"
        f"{_format_list(llm_result.get('recommendations', []), '✓', lang)}",
        f"──────────────────────────────────────────────\n{t(lang, 'verdict_disclaimer')}",
    ]

    if keyword_result["suspicious"]:
        matches = escape(", ".join(keyword_result["matches"]))
        lines.insert(3, f"⚠️ <b>{t(lang, 'keyword_match_label')}:</b> <code>{matches}</code>")

    return "\n\n".join(lines)


def format_unified_response(unified: dict, keyword_result: dict, lang: str = DEFAULT_LANG) -> str:
    """Same visual shape as format_analysis_response, but key_reasons are
    {text, source} objects (context_engine.py's schema) instead of plain
    strings, so a reason that came from checking a link can be tagged 🔗
    - the "why" for a verdict a link-only or text-only check couldn't
    have produced on its own.

    Unlike format_analysis_response, this one IS lang-aware: the fixed
    labels/headers come from i18n.py, and the dynamic key_reasons/
    recommendations text is expected to already be in the target
    language (analyze_unified asks Gemini to respond in it directly -
    see context_engine.py).

    unified["ai_unavailable"] (set by context_engine.py's
    _grounded_fallback) means there's no AI-authored reasons/
    recommendations text to show at all - the Key Reasons/What To Do
    sections are replaced with one fixed, translated notice instead of
    a body that would otherwise mix raw English boilerplate into an
    otherwise-Khmer reply, or a "None provided" What To Do section."""
    verdict_icon, verdict_label = verdict_style(unified.get("verdict"), lang)
    risk_icon, risk_label = risk_style(unified.get("risk_percentage"), lang)
    risk_percentage = unified.get("risk_percentage")
    percentage = f"{risk_percentage}%" if risk_percentage is not None else "N/A"

    header = (
        f"{verdict_icon} <b>{t(lang, 'verdict_label')}: {escape(verdict_label)}</b>\n\n"
        + _summary(unified.get("verdict"), risk_percentage, lang)
    )
    risk_block = f"{risk_icon} <b>{percentage}  {risk_label.upper()}</b>"

    if unified.get("ai_unavailable"):
        lines = [
            header,
            f"{risk_block}\n\n⚠️ {escape(t(lang, 'ai_unavailable_notice'))}",
            f"──────────────────────────────────────────────\n{t(lang, 'verdict_disclaimer')}",
        ]
        if keyword_result["suspicious"]:
            matches = escape(", ".join(keyword_result["matches"]))
            lines.insert(2, f"⚠️ <b>{t(lang, 'keyword_match_label')}:</b> <code>{matches}</code>")
        return "\n\n".join(lines)

    reason_items = unified.get("key_reasons") or []
    if reason_items:
        reason_lines = []
        for r in reason_items:
            text, source = (r.get("text", ""), r.get("source")) if isinstance(r, dict) else (str(r), None)
            tag = SOURCE_TAGS.get(source, "")
            reason_lines.append(f"• {escape(text)}{tag}")
        reasons_block = "\n".join(reason_lines)
    else:
        reasons_block = f"• {t(lang, 'none_provided')}"

    lines = [
        header,
        f"{risk_block}\n\n"
        f"🔍 <b>{t(lang, 'key_reasons_header')}</b>\n{reasons_block}",
        f"💡 <b>{t(lang, 'what_to_do_header')}</b>\n"
        f"{_format_list(unified.get('recommendations', []), '✓', lang)}",
        f"──────────────────────────────────────────────\n{t(lang, 'verdict_disclaimer')}",
    ]

    if keyword_result["suspicious"]:
        matches = escape(", ".join(keyword_result["matches"]))
        lines.insert(3, f"⚠️ <b>{t(lang, 'keyword_match_label')}:</b> <code>{matches}</code>")

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

    if canonical_key in _MENU_RESPONSE_KEYS:
        await update.message.reply_text(
            t(lang, canonical_key),
            parse_mode="HTML",
            reply_markup=main_menu_keyboard,
        )
        return

    keyword_result = analyze_text(text)

    # Plain private DM: reason over text AND any link together in one
    # Gemini call, instead of the link-only verdict a private-chat link
    # used to fall back to. See bot/context_engine.py for why this
    # exists - a text-only scam that includes ANY link, even a
    # lexically clean one, used to lose all of its text reasoning here.
    # Business chat never reaches this function at all (route.py's
    # TEXT_FILTER excludes it) - it's fully owned by
    # url_checker/message/handler.handle_business_message, whose
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
        has_links = bool(URL_REGEX.search(text)) or bool(hidden_links)
        status = None
        if has_links or document is not None:
            status = await message.reply_text(t(lang, "checking_status"), parse_mode="Markdown")

        async def _check_file():
            sha256 = await download_and_hash(context, document.file_id)
            return await scan_vt_hash(sha256)

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

        unified = await analyze_unified(text, keyword_result, link_verdicts, file_verdict, lang)
        reply_text = format_unified_response(unified, keyword_result, lang)

        if status is not None:
            await status.edit_text(reply_text, parse_mode="HTML", disable_web_page_preview=True)
        else:
            await message.reply_text(reply_text, parse_mode="HTML", reply_markup=main_menu_keyboard)
        return

    # Group/supergroup chat: unchanged text-only reasoning - any link in
    # the message is still checked separately by url_checker's own
    # handle_url flow.
    llm_result = await analyze_text_with_llm(text)

    await message.reply_text(
        format_analysis_response(llm_result, keyword_result),
        parse_mode="HTML",
        reply_markup=main_menu_keyboard,
    )