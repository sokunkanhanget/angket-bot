import logging

from telegram import Update
from telegram.ext import (
    Application,
    BusinessConnectionHandler,
    CallbackQueryHandler,
    CommandHandler,
    MessageHandler,
    filters,
    TypeHandler,
)

from bot.analysis.utils import init_db, init_url_db
from bot.config import GEMINI_API_KEY, TELEGRAM_BOT_TOKEN, VIRUSTOTAL_API_KEY
from bot.handlers.file_handler import handle_file
from bot.handlers.text_handler import handle_text, start
from bot.url_checker.message.handler import (
    handle_business_url_callback,
    handle_photo,
    handle_url,
    on_business_connection,
)
from bot.route import TEXT_FILTER

# Feature ownership:
#   bot/url_checker/  — link checking (BB)
#   text_handler / file_handler / llm_analyzer — teammates' text & file scanning
#   bot/context_engine.py — merges both, for plain private DM only (see below)
# Shared infra lives in bot/analysis/utils.py so both log to one DB.
#
# Handler groups (PTB runs every group per update, independently; within
# a group, only the FIRST matching handler runs, so anything meant to
# fire alongside another check needs its own group):
#   group 0  — /start menu, file scan, business-connection plumbing
#   group 1  — link checker (text or caption; silent when no links).
#              Excludes plain PRIVATE chat — see below.
#   group 2  — QR-in-photo decode (own group so a caption link match in
#              group 1 can never shadow it for the same photo message)
#   group 3  — teammate's text/LLM scan (text or caption)
# Separate groups by design, except group 3 skips business messages that
# already have a link (still handled by group 1's owner-DM flow) — see
# bot/route.py. Plain PRIVATE chat is different from both group/business:
# handle_text (group 3) now runs there UNCONDITIONALLY, and internally
# checks any link itself and reasons about it together with the message
# text in one Gemini call (bot/context_engine.py) — group 1's url_filter
# explicitly excludes plain private chat so that link doesn't also get a
# second, uncoordinated reply from the old link-only flow.

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=logging.INFO,
)
# httpx logs the full request URL at INFO, and PTB embeds the bot token
# directly in that URL (https://api.telegram.org/bot<TOKEN>/...) — quiet
# it down so the token never hits stdout/log files.
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


def validate_config() -> bool:
    """Fail fast at startup instead of mysteriously mid-flight."""
    if not TELEGRAM_BOT_TOKEN:
        logger.error("Missing TELEGRAM_BOT_TOKEN in .env file.")
        return False
    if not VIRUSTOTAL_API_KEY:
        # Not fatal: Flow 3 just stays offline and the other flows
        # keep working. But say so loudly so it's never a surprise.
        logger.warning("VIRUSTOTAL_API_KEY not set — threat-intelligence "
                       "flow disabled; running with local analysis only.")
    if not GEMINI_API_KEY:
        logger.warning("GEMINI_API_KEY not set — LLM text analysis disabled; "
                       "text checks fall back to keyword matching only.")
    return True



def main():
    if not validate_config():
        return

    init_db()
    init_url_db()
    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    async def _log_every_update(update, context):
        logger.debug(
            "update: message=%s edited=%s business=%s callback=%s",
            update.message, update.edited_message,
            update.business_message, update.callback_query,
        )

    async def _on_error(update, context):
        logger.exception("handler error for update %s", update, exc_info=context.error)

    app.add_handler(TypeHandler(Update, _log_every_update), group=-1)  # group=-1 = runs first, logs, doesn't block
    app.add_error_handler(_on_error)

    # /start: teammate's welcome menu. When the deep link carries a
    # ticket (?start=<ticket> from a link-checker showcase), it shows
    # the saved full breakdown instead — see text_handler.start.
    app.add_handler(CommandHandler("start", start))

    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))

    # Keeps the business-connection -> owner-chat-id cache warm (see
    # url_checker/message/handler.on_business_connection for why this matters).
    app.add_handler(BusinessConnectionHandler(on_business_connection))

    # "See full details" / "Show less detail" / "Delete" taps on the
    # owner's private business-link notifications.
    app.add_handler(CallbackQueryHandler(handle_business_url_callback, pattern=r"^u:"))

    # Link checker — text or caption, GROUP/supergroup chat or Telegram
    # Business messages; silent when no links are found. Plain PRIVATE
    # chat is excluded here on purpose: handle_text now checks and
    # reasons over any link there itself, in the same call as the message
    # text (see bot/context_engine.py) - this filter firing there too
    # would produce a second, uncoordinated reply for the same link.
    # Own group so it always runs alongside the QR decode and text/LLM
    # scan below, even when all three match the same photo-with-caption
    # message in a group chat.
    url_filter = (
        (filters.TEXT | filters.CAPTION) & ~filters.COMMAND & ~filters.ChatType.PRIVATE
    ) | filters.UpdateType.BUSINESS_MESSAGE
    app.add_handler(MessageHandler(url_filter, handle_url), group=1)

    # QR codes shared as photos are invisible to handle_url's text/caption
    # regex - decodes any QR code found and runs it through the same
    # link-checking pipeline. Own group: url_filter also matches a photo's
    # caption (if any) or any business message, so sharing a group with it
    # would let that match shadow this one and skip the QR decode entirely.
    photo_filter = filters.PHOTO | filters.UpdateType.BUSINESS_MESSAGE
    app.add_handler(MessageHandler(photo_filter, handle_photo), group=2)

    # Teammate's text/LLM scan — text or caption, normal chat or Business
    # messages (PTB's filters check update.effective_message under the
    # hood, so business messages satisfy filters.TEXT/CAPTION). Own group
    # so a document's caption doesn't get shadowed by handle_file's
    # earlier, unconditional match on the same message in group 0.
    # Filtered by bot/route.py to skip messages the link checker already
    # covers.
    app.add_handler(MessageHandler(TEXT_FILTER, handle_text), group=3)

    logger.info("Bot is running...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)  # ALL_TYPES so business_message actually gets delivered



if __name__ == "__main__":
    main()
