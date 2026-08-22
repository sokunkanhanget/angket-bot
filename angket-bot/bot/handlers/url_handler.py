"""
bot/handlers/url_handler.py
===========================
Telegram wiring for URL checking. Thin on purpose — the real logic
lives in bot/analysis/url_analyzer.py.

Pattern: send a "Checking..." message first, then EDIT it into the
result (like file_handler.py does with its "Scanning..." message).
"""

from telegram import Update
from telegram.ext import ContextTypes

from bot.analysis.url_analyzer import check_message, format_verdict
from bot.analysis.utils import log_url_scan


async def handle_url(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Guard: skip updates that aren't real text messages.
    if update.message is None or update.message.text is None:
        return

    text = update.message.text
    user_id = update.effective_user.id

    verdicts = check_message(text)

    # No links → this handler only speaks about URLs.
    if not verdicts:
        await update.message.reply_text("🔗 No links found in that message.")
        return

    # Step 1: send a placeholder we can edit into the result.
    status = await update.message.reply_text("🔍 *Checking link...*", parse_mode="Markdown")

    # Build one combined reply for all links found.
    parts = []
    for verdict in verdicts:
        parts.append(format_verdict(verdict))
        # Log every checked URL to the database.
        log_url_scan(user_id, verdict["host"], verdict["score"], verdict["level"])

    reply = "\n\n———\n\n".join(parts)

    # Step 2: edit the placeholder into the final verdict.
    await status.edit_text(
        reply,
        parse_mode="Markdown",
        disable_web_page_preview=True,  # don't preview a possibly-bad link
    )