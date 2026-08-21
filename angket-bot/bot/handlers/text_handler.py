from telegram import Update
from telegram.ext import ContextTypes

from bot.analysis.text_analyzer import analyze_text


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "🛡️ **Angket Bot**\n\n"
        "Send me a file or text string to perform a malware scan.",
        parse_mode="Markdown",
    )


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text or ""
    result = analyze_text(text)
    if result["suspicious"]:
        matches = ", ".join(result["matches"])
        reply = f"⚠️ **SUSPICIOUS TEXT DETECTED**\n\nMatched: `{matches}`"
    else:
        reply = "🟢 **TEXT LOOKS CLEAN**\n\nNo suspicious patterns were detected."
    await update.message.reply_text(reply, parse_mode="Markdown")