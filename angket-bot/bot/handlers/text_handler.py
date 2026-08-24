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
            return "This looks a bit suspicious, a few things about it don't add up. Be careful with it."
        return "This really looks like a scam. We'd strongly recommend not acting on it."
    if verdict == "Not a Scam":
        if risk_percentage is not None and risk_percentage > 30:
            return "This seems mostly fine, but a couple of small things stood out. Just double-check before you act."
        return "This message looks safe, we didn't spot anything concerning."
    if risk_percentage is not None and risk_percentage > 60:
        return "Something feels off here. Best to avoid sharing any personal details."
    if risk_percentage is not None and risk_percentage > 30:
        return "A few red flags popped up. Worth verifying before you do anything with this."
    return "We couldn't tell for sure whether this is safe or not because of not enough information to go on."


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
        f"{risk_icon} <b>SCAM RISK</b>: <b>{percentage} - {risk_label.upper()}</b>\n\n"
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
    keyword_result = analyze_text(text)
    llm_result = await analyze_text_with_llm(text)

    await update.message.reply_text(
        format_analysis_response(llm_result, keyword_result), parse_mode="HTML"
    )