from html import escape

from telegram import ReplyKeyboardMarkup, Update
from telegram.ext import ContextTypes

from bot.analysis.llm_analyzer import analyze_text_with_llm
from bot.analysis.text_analyzer import analyze_text
from bot.context_engine import analyze_unified
from bot.i18n import DEFAULT_LANG, BUTTONS, key_for_label, label, t
from bot.url_checker.features.offline.lexical import URL_REGEX
from bot.url_checker.features.offline.vectors import ensure_seeded as ensure_vectors_seeded
from bot.url_checker.message.handler import extract_text_link_entities, resolve_ticket
from bot.url_checker.pipeline import check_message_full
from bot.verdict_style import SOURCE_TAGS, VERDICT_STYLES, risk_style

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


_DISCLAIMER = (
    "ⓘ Angket Bot may occasionally make mistakes.\n"
    "Double-check important information before taking action."
)


def _format_list(items: list, prefix: str) -> str:
    if not items:
        return f"{prefix} None provided"
    return "\n".join(f"{prefix} {escape(str(item))}" for item in items)


def _summary(verdict: str | None, risk_percentage: int | None) -> str:
    if verdict == "Scam":
        if risk_percentage is not None and risk_percentage <= 60:
            return "This message has warning signs. Verify it before taking action."
        return "This message shows strong signs of being unsafe."
    if verdict == "Not a Scam":
        if risk_percentage is not None and risk_percentage > 30:
            return "This message has warning signs. Verify it before taking action."
        return "No strong scam indicators were detected in this message."
    if risk_percentage is not None and risk_percentage > 60:
        return "This message shows strong signs of being unsafe."
    if risk_percentage is not None and risk_percentage > 30:
        return "This message has warning signs. Verify it before taking action."
    return "No strong scam indicators were detected in this message."


def format_analysis_response(llm_result: dict, keyword_result: dict) -> str:
    verdict_icon, verdict_label = VERDICT_STYLES.get(
        llm_result.get("verdict"), ("⚪", "UNABLE TO VERIFY")
    )
    risk_icon, risk_label = risk_style(llm_result.get("risk_percentage"))
    risk_percentage = llm_result.get("risk_percentage")
    percentage = f"{risk_percentage}%" if risk_percentage is not None else "N/A"

    lines = [
        f"{verdict_icon} <b>VERDICT: {escape(verdict_label)}</b>\n\n"
        + _summary(llm_result.get("verdict"), risk_percentage),
        f"{risk_icon} <b>{percentage}  {risk_label.upper()}</b>\n\n"
        f"🔍 <b>KEY REASONS</b>\n{_format_list(llm_result.get('key_reasons', []), '•')}",
        "💡 <b>WHAT YOU SHOULD DO</b>\n"
        f"{_format_list(llm_result.get('recommendations', []), '✓')}",
        f"──────────────────────────────────────────────\n{_DISCLAIMER}",
    ]

    if keyword_result["suspicious"]:
        matches = escape(", ".join(keyword_result["matches"]))
        lines.insert(3, f"⚠️ <b>KEYWORD MATCH:</b> <code>{matches}</code>")

    return "\n\n".join(lines)


def format_unified_response(unified: dict, keyword_result: dict) -> str:
    """Same visual shape as format_analysis_response, but key_reasons are
    {text, source} objects (context_engine.py's schema) instead of plain
    strings, so a reason that came from checking a link can be tagged 🔗
    - the "why" for a verdict a link-only or text-only check couldn't
    have produced on its own."""
    verdict_icon, verdict_label = VERDICT_STYLES.get(
        unified.get("verdict"), ("⚪", "UNABLE TO VERIFY")
    )
    risk_icon, risk_label = risk_style(unified.get("risk_percentage"))
    risk_percentage = unified.get("risk_percentage")
    percentage = f"{risk_percentage}%" if risk_percentage is not None else "N/A"

    reason_items = unified.get("key_reasons") or []
    if reason_items:
        reason_lines = []
        for r in reason_items:
            text, source = (r.get("text", ""), r.get("source")) if isinstance(r, dict) else (str(r), None)
            tag = SOURCE_TAGS.get(source, "")
            reason_lines.append(f"• {escape(text)}{tag}")
        reasons_block = "\n".join(reason_lines)
    else:
        reasons_block = "• None provided"

    lines = [
        f"{verdict_icon} <b>VERDICT: {escape(verdict_label)}</b>\n\n"
        + _summary(unified.get("verdict"), risk_percentage),
        f"{risk_icon} <b>{percentage}  {risk_label.upper()}</b>\n\n"
        f"🔍 <b>KEY REASONS</b>\n{reasons_block}",
        "💡 <b>WHAT YOU SHOULD DO</b>\n"
        f"{_format_list(unified.get('recommendations', []), '✓')}",
        f"──────────────────────────────────────────────\n{_DISCLAIMER}",
    ]

    if keyword_result["suspicious"]:
        matches = escape(", ".join(keyword_result["matches"]))
        lines.insert(3, f"⚠️ <b>KEYWORD MATCH:</b> <code>{matches}</code>")

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

        hidden_links = extract_text_link_entities(message)
        has_links = bool(URL_REGEX.search(text)) or bool(hidden_links)
        status = None
        if has_links:
            status = await message.reply_text("🔍 Checking...", parse_mode="Markdown")

        link_verdicts = await check_message_full(text, hidden_links)
        unified = await analyze_unified(text, keyword_result, link_verdicts)
        reply_text = format_unified_response(unified, keyword_result)

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