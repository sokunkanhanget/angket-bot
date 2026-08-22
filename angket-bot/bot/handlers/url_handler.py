"""
bot/handlers/url_handler.py
===========================
Telegram wiring for URL checking. Thin on purpose — all the real logic
lives in bot/analysis/url_analyzer.py. This mirrors the shape of
text_handler.py: read the message, analyze, reply.

The user sends or FORWARDS a message to the bot; forwarded text still
arrives as update.message.text, so we read it the same way.
"""

from telegram import Update
from telegram.ext import ContextTypes

from bot.analysis.url_analyzer import check_message, format_verdict


async def handle_url(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text or ""
    verdicts = check_message(text)

    # No links in the message — this handler only speaks about URLs.
    if not verdicts:
        await update.message.reply_text(
            "🔗 No links found in that message.",
        )
        return

    # One reply per link found, each with its full breakdown.
    for verdict in verdicts:
        await update.message.reply_text(
            format_verdict(verdict),
            parse_mode="Markdown",
            disable_web_page_preview=True,  # don't preview a possibly-bad link
        )