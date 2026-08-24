from html import escape

from telegram import Update
from telegram.ext import ContextTypes

from bot.analysis.llm_analyzer import analyze_text_with_llm
from bot.analysis.text_analyzer import analyze_text


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "🛡️ <b>Welcome to Angket Bot</b>\n"
        "Your security assistant for checking suspicious content.\n\n"
        "🔍 What can I scan?\n"
        "• 📝 Text messages\n"
        "• 📄 Files\n"
        "• 🔗 URLs & links\n\n"
        "Simply send me something, and I’ll analyze it for security threats.\n\n"
        "Let’s keep your digital world safer.",
        parse_mode="HTML",
    )


_VERDICT_STYLES = {
    "Scam": ("⚠️", "Likely a SCAM"),
    "Not a Scam": ("✅", "SAFE / LEGITIMATE"),
    "Uncertain": ("⚠️", "SUSPICIOUS"),
}

_DISCLAIMER = (
    "ⓘ Our bot can make mistakes sometimes.\n"
    "Please double-check important information before taking any action.\n"
    "Stay safe! 🛡"
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


def _section(content: str) -> str:
    return f"<blockquote>{content}</blockquote>"


def format_analysis_response(llm_result: dict, keyword_result: dict) -> str:
    verdict_icon, verdict_label = _VERDICT_STYLES.get(
        llm_result.get("verdict"), ("⚪", "UNABLE TO VERIFY")
    )
    risk_icon, risk_label = _risk_style(llm_result.get("risk_percentage"))
    risk_percentage = llm_result.get("risk_percentage")
    percentage = f"{risk_percentage}%" if risk_percentage is not None else "N/A"

    lines = [
        _section(
            f"{verdict_icon} <b>Verdict: {escape(verdict_label)}</b>\n"
            f"<i>This link shows strong signs of being unsafe.</i>"
        ),
        _section(
            f"🛡 <b>Scam Risk Level</b> {risk_icon} <b>{percentage}%</b> <b>{risk_label}</b>"
        ),
        _section(
            f"🔍 <b>Key Reasons</b>\n"
            f"{_format_list(llm_result.get('key_reasons', []), '•')}"
        ),
        _section(
            f"💡 <b>What You Can Do</b>\n"
            f"<blockquote>{_format_list(llm_result.get('recommendations', []), '✅')}</blockquote>"
        ),
        f"<i>{_DISCLAIMER}</i>",
    ]

    if keyword_result["suspicious"]:
        matches = escape(", ".join(keyword_result["matches"]))
        lines.insert(0, f"⚠️ <b>Keyword match:</b> <code>{matches}</code>")

    return "\n\n".join(lines)


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text or ""
    keyword_result = analyze_text(text)
    llm_result = await analyze_text_with_llm(text)

    await update.message.reply_text(
        format_analysis_response(llm_result, keyword_result), parse_mode="HTML"
    )