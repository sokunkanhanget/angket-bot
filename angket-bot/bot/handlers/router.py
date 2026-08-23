from telegram import Update
from telegram.ext import ContextTypes

# NOTE (link-checker owner): url_analyzer moved into the linkchecker
# package — only this import line was updated, logic untouched.
from bot.linkchecker.lexical import check_message, format_verdict
from bot.analysis.text_analyzer import analyze_text

async def route_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message is None or update.message.text is None:
        return

    text = update.message.text

    verdicts = check_message(text)

    if verdicts:
        for v in verdicts:
            await update.message.reply_text(
                format_verdict(v),
                parse_mode="Markdown",
                disable_web_page_preview=True,
            )
    else:
        result = analyze_text(text)
        if result["suspicious"]:
            matches = ", ".join(result["matches"])
            await update.message.reply_text(
                f"Sus text detected\n\n matched: `{matches}`",
                parse_mode="Markdown",
            )
        else:
            await update.message.reply_text(
                "text so clean, I might be gay",
                parse_mode="Markdown"
            )