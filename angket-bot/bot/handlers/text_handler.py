from telegram import Update
from telegram.ext import ContextTypes

from bot.analysis.llm_analyzer import analyze_text_with_llm
from bot.analysis.text_analyzer import analyze_text


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "🛡️ **Angket Bot**\n\n"
        "Send me a file or text string to perform a malware scan.",
        parse_mode="Markdown",
    )


_VERDICT_ICONS = {
    "Scam": "🚨",
    "Not a Scam": "🟢",
    "Uncertain": "⚪",
}

_DISCLAIMER = (
    "⚠️ Angket can make mistakes. Please double check important information "
    "before taking any action. Stay safe."
)


def _format_list(items: list) -> str:
    if not items:
        return "- None provided"
    return "\n".join(f"- {item}" for item in items)


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text or ""
    keyword_result = analyze_text(text)
    llm_result = await analyze_text_with_llm(text)

    lines = []
    if keyword_result["suspicious"]:
        matches = ", ".join(keyword_result["matches"])
        lines.append(f"⚠️ **Keyword match:** `{matches}`")

    verdict = llm_result["verdict"]
    icon = _VERDICT_ICONS.get(verdict, "⚪")
    risk_percentage = llm_result["risk_percentage"]
    risk_suffix = f" ({risk_percentage}%)" if risk_percentage is not None else ""

    lines.append(f" **Verdict:** {icon} {verdict}")
    lines.append(f"📊 **Scam Risk Level:** {llm_result['risk_level']}{risk_suffix}")
    lines.append(f"🔍 **Key Reasons:**\n{_format_list(llm_result['key_reasons'])}")
    lines.append(f"🛡️ **What You Can Do:**\n{_format_list(llm_result['recommendations'])}")
    lines.append(f"** {_DISCLAIMER}")

    await update.message.reply_text("\n\n".join(lines), parse_mode="Markdown")