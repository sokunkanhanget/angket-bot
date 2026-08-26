from html import escape

from telegram import ReplyKeyboardMarkup, Update
from telegram.ext import ContextTypes

from bot.analysis.llm_analyzer import analyze_text_with_llm
from bot.analysis.text_analyzer import analyze_text
from bot.linkchecker.handler import resolve_ticket

BTN_MENU = "MENU"
BTN_SWITCH_LANGUAGE = "🌐 Switch Language"
BTN_HOW_TO_USE = "📖 How to Use"
BTN_SAFETY_TIPS = "🛡️ Safety Tips"
BTN_LIVE_SCAN = "🔎 Live Message Scan"
BTN_POLICY = "📜 Policy"
BTN_HELP = "❓ Help"
BTN_SUBSCRIPTION = "⭐ Subscription"

TRIGGER_MENU_KEYBOARD = ReplyKeyboardMarkup(
    [[BTN_MENU]],
    resize_keyboard=True,
    one_time_keyboard=True,
)

MAIN_MENU_KEYBOARD = ReplyKeyboardMarkup(
    [
        [BTN_SWITCH_LANGUAGE, BTN_HOW_TO_USE],
        [BTN_SAFETY_TIPS, BTN_LIVE_SCAN],
        [BTN_POLICY, BTN_HELP],
        [BTN_SUBSCRIPTION],
    ],
    resize_keyboard=True,
)

_MENU_RESPONSES = {
    BTN_SWITCH_LANGUAGE: "🌐 <b>Switch Language</b>\n\nLanguage selection is coming soon.",
    BTN_HOW_TO_USE: (
        "📖 <b>How to Use</b>\n\n"
        "Simply send me a text message, file, or link and I’ll analyze it for security threats."
    ),
    BTN_SAFETY_TIPS: (
        "🛡️ <b>Safety Tips</b>\n\n"
        "• Never share OTPs, passwords, or bank details.\n"
        "• Verify links before clicking.\n"
        "• Be cautious of urgent or too-good-to-be-true offers."
    ),
    BTN_LIVE_SCAN: "🔎 <b>Live Message Scan</b>\n\nSend me any message and I’ll scan it in real time.",
    BTN_POLICY: "📜 <b>Policy</b>\n\nOur privacy and usage policy will be shown here.",
    BTN_HELP: "❓ <b>Help</b>\n\nNeed assistance? Just send your question and we'll do our best to help.",
    BTN_SUBSCRIPTION: "⭐ <b>Subscription</b>\n\nSubscription plans are coming soon.",
}

BTN_MENU = "MENU"
BTN_SWITCH_LANGUAGE = "🌐 Switch Language"
BTN_HOW_TO_USE = "📖 How to Use"
BTN_SAFETY_TIPS = "🛡️ Safety Tips"
BTN_LIVE_SCAN = "🔎 Live Message Scan"
BTN_POLICY = "📜 Policy"
BTN_HELP = "❓ Help"
BTN_SUBSCRIPTION = "⭐ Subscription"

TRIGGER_MENU_KEYBOARD = ReplyKeyboardMarkup(
    [[BTN_MENU]],
    resize_keyboard=True,
    one_time_keyboard=True,
)

MAIN_MENU_KEYBOARD = ReplyKeyboardMarkup(
    [
        [BTN_SWITCH_LANGUAGE, BTN_HOW_TO_USE],
        [BTN_SAFETY_TIPS, BTN_LIVE_SCAN],
        [BTN_POLICY, BTN_HELP],
        [BTN_SUBSCRIPTION],
    ],
    resize_keyboard=True,
)

_MENU_RESPONSES = {
    BTN_SWITCH_LANGUAGE: "🌐 <b>Switch Language</b>\n\nLanguage selection is coming soon.",
    BTN_HOW_TO_USE: (
        "📖 <b>How to Use</b>\n\n"
        "Simply send me a text message, file, or link and I’ll analyze it for security threats."
    ),
    BTN_SAFETY_TIPS: (
        "🛡️ <b>Safety Tips</b>\n\n"
        "• Never share OTPs, passwords, or bank details.\n"
        "• Verify links before clicking.\n"
        "• Be cautious of urgent or too-good-to-be-true offers."
    ),
    BTN_LIVE_SCAN: "🔎 <b>Live Message Scan</b>\n\nSend me any message and I’ll scan it in real time.",
    BTN_POLICY: "📜 <b>Policy</b>\n\nOur privacy and usage policy will be shown here.",
    BTN_HELP: "❓ <b>Help</b>\n\nNeed assistance? Just send your question and we'll do our best to help.",
    BTN_SUBSCRIPTION: "⭐ <b>Subscription</b>\n\nSubscription plans are coming soon.",
}


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
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
        reply_markup=MAIN_MENU_KEYBOARD,
    )


_VERDICT_STYLES = {
    "Scam": ("⚠️", "LIKELY A SCAM"),
    "Not a Scam": ("✅", "SAFE / LEGITIMATE"),
    "Uncertain": ("⚠️", "SUSPICIOUS"),
}

_DISCLAIMER = (
    "ⓘ Angket Bot may occasionally make mistakes.\n"
    "Double-check important information before taking action.\n\n"
    "🛡️ <b>Stay safe!</b>"
)


def _format_list(items: list, prefix: str) -> str:
    if not items:
        return f"{prefix} None provided"
    return "\n".join(f"{prefix} {escape(str(item))}" for item in items)


def _risk_style(risk_percentage: int | None) -> tuple[str, str]:
    if risk_percentage is None:
        return "⚪", "Unknown Risk"
    if risk_percentage <= 30:
        return "🟢", "Low Risk"
    if risk_percentage <= 60:
        return "🟠", "Medium Risk"
    return "🔴", "High Risk"


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
    verdict_icon, verdict_label = _VERDICT_STYLES.get(
        llm_result.get("verdict"), ("⚪", "UNABLE TO VERIFY")
    )
    risk_icon, risk_label = _risk_style(llm_result.get("risk_percentage"))
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


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text or ""

    if text.upper() == BTN_MENU:
        await update.message.reply_text(
            "📋 <b>Menu</b>\n\nChoose an action below.",
            parse_mode="HTML",
            reply_markup=MAIN_MENU_KEYBOARD,
        )
        return

    menu_response = _MENU_RESPONSES.get(text)
    if menu_response is not None:
        await update.message.reply_text(
            menu_response,
            parse_mode="HTML",
            reply_markup=MAIN_MENU_KEYBOARD,
        )
        return

    keyword_result = analyze_text(text)
    llm_result = await analyze_text_with_llm(text)

    await update.message.reply_text(
        format_analysis_response(llm_result, keyword_result),
        parse_mode="HTML",
        reply_markup=MAIN_MENU_KEYBOARD,
    )