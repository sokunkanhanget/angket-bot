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
from bot.linkchecker.handler import (
    handle_business_url_callback,
    handle_url,
    on_business_connection,
)
from bot.route import TEXT_FILTER

# Feature ownership:
#   bot/linkchecker/  — link checking (BB)
#   text_handler / file_handler / llm_analyzer — teammates' text & file scanning
# Shared infra lives in bot/analysis/utils.py so both log to one DB.
#
# Handler groups (PTB runs every group per update, independently):
#   group 0  — teammate's text/LLM scan + file scan + /start menu
#   group 1  — link checker showcase (silent when a message has no links)
# Separate replies by design, except group 0 skips private/business
# messages that already have a link — see bot/route.py.

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=logging.INFO,
)
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
    # linkchecker/handler.on_business_connection for why this matters).
    app.add_handler(BusinessConnectionHandler(on_business_connection))

    # "See full details" / "Show less detail" / "Delete" taps on the
    # owner's private business-link notifications.
    app.add_handler(CallbackQueryHandler(handle_business_url_callback, pattern=r"^u:"))

    # Teammate's text/LLM scan — normal chat text AND Telegram Business
    # messages (PTB's filters check update.effective_message under the
    # hood, so business messages satisfy filters.TEXT). Filtered by
    # bot/route.py to skip messages the link checker already covers.
    app.add_handler(MessageHandler(TEXT_FILTER, handle_text), group=0)

    # Link checker — same updates, separate group so both scans run and
    # answer independently; silent when no links are found.
    url_filter = (filters.TEXT & ~filters.COMMAND) | filters.UpdateType.BUSINESS_MESSAGE
    app.add_handler(MessageHandler(url_filter, handle_url), group=1)

    logger.info("Bot is running...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)  # ALL_TYPES so business_message actually gets delivered



if __name__ == "__main__":
    main()
