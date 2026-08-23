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

from bot.analysis.utils import init_url_db
from bot.config import TELEGRAM_BOT_TOKEN, VIRUSTOTAL_API_KEY
from bot.linkchecker.handler import (
    handle_business_url_callback,
    handle_url,
    on_business_connection,
    start,
)

# NOTE: file scanning (bot.handlers.file_handler) and free-text keyword
# scanning (bot.handlers.text_handler) are owned by a teammate on a
# separate branch. This branch wires up links only — everything it
# needs (including its own /start landing page for the DM deep link)
# lives in url_handler.py, so it doesn't touch their files and there's
# nothing here to conflict with when their branch merges in.

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
    return True


def main():
    if not validate_config():
        return

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

    app.add_handler(CommandHandler("start", start))  # also serves as the deep-link landing page for url_handler

    # Keeps the business-connection -> owner-chat-id cache warm (see
    # url_handler.on_business_connection for why this matters).
    app.add_handler(BusinessConnectionHandler(on_business_connection))

    # "See full details" / "Show less detail" / "Delete" taps on the
    # owner's private business-link notifications.
    app.add_handler(CallbackQueryHandler(handle_business_url_callback, pattern=r"^u:"))

    # One handler covers normal chat text AND Telegram Business messages.
    # (Business messages arrive on update.business_message, not
    # update.message, but they still satisfy filters.TEXT because PTB's
    # filters check update.effective_message under the hood.)
    url_filter = (filters.TEXT & ~filters.COMMAND) | filters.UpdateType.BUSINESS_MESSAGE
    app.add_handler(MessageHandler(url_filter, handle_url))

    logger.info("Bot is running...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)  # ALL_TYPES so business_message actually gets delivered


if __name__ == "__main__":
    main()