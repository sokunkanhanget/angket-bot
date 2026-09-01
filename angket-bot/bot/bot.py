import asyncio
import logging
import sys

# psycopg's async mode (bot/url_checker/features/offline/vectors.py's
# Supabase pgvector pool) can't run on Windows' default ProactorEventLoop
# - must switch BEFORE any event loop is created, which is why this is
# module-level, at the very top, ahead of anything that could start one.
# No-op (and WindowsSelectorEventLoopPolicy doesn't even exist) on
# Linux/Mac, where this was never an issue.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

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
from bot.config import GEMINI_API_KEY, SUPABASE_DB_URL, TELEGRAM_BOT_TOKEN, VIRUSTOTAL_API_KEY
from bot.handlers.file_handler import handle_file, handle_scan_action_callback
from bot.handlers.text_handler import handle_text, start
from bot.url_checker.message.handler import (
    handle_business_message,
    handle_business_url_callback,
    handle_url,
    on_business_connection,
)
from bot.route import TEXT_FILTER

# Feature ownership:
#   bot/url_checker/  — link checking (BB)
#   text_handler / file_handler / llm_analyzer — teammates' text & file scanning
#   bot/context_engine.py — merges both, for plain private DM and Business
#     chat automation (see below)
# Shared infra lives in bot/analysis/utils.py so both log to one DB.
#
# Handler groups (PTB runs every group per update, independently; within
# a group, only the FIRST matching handler runs, so anything meant to
# fire alongside another check needs its own group):
#   group 0  — /start menu, file scan (non-Business only) + its
#              Delete/Ignore result buttons, business-connection plumbing
#   group 1  — link checker (text or caption; silent when no links).
#              GROUP/supergroup chat only — see below.
#   group 2  — teammate's text/LLM scan (text or caption). GROUP/supergroup
#              and plain PRIVATE chat only — see below.
#   group 3  — Business chat automation: ONE unified text+link+file check
#              per message (bot/context_engine.py + handle_business_message)
#
# No image/photo scanning (e.g. QR decoding) anywhere - text, links, and
# files only, per team decision.
#
# Plain PRIVATE chat: handle_text (group 2) runs there UNCONDITIONALLY and
# internally checks any link itself, reasoning about it together with the
# message text in one Gemini call — group 1's url_filter excludes plain
# private chat so that link doesn't also get a second, uncoordinated reply.
#
# Business chat: fully owned by group 3 now. A Business connection lets a
# user automate their own chat with Angket — every customer message (text,
# link, or file, including a photo's caption) is checked together in one
# call and privately reported to the owner (see
# url_checker/message/handler.handle_business_message). Groups 0/1/2's
# filters all exclude Business messages so this is the only thing that
# fires for them — group 0's old file-scan path used to crash on a
# Business document (it read update.message, which is None for Business
# messages; the actual message is update.business_message) and group 2's
# old text-only path replied directly in the business chat, visible to the
# customer, contradicting the owner-DM privacy model every other business
# notification in this project uses.

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
    if not SUPABASE_DB_URL:
        # Not fatal: seeding/nearest() already degrade to "no evidence"
        # on any DB error (see vectors.py's ensure_seeded and
        # context_engine.py's _grounded_fallback) rather than crashing a
        # handler. But a missing connection string means EVERY link/text
        # check silently loses brand/phish/seen/scam-pattern similarity,
        # so this should be loud at boot, not discovered mid-flight from
        # an obscure psycopg error inside the first real user message.
        logger.warning("SUPABASE_DB_URL not set — vector-similarity checks "
                       "(brand/phish/seen/scam-pattern matching) disabled.")
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

    # Business documents are handled by group 3's handle_business_message
    # instead - this used to also match Business messages and crash
    # (update.message is None there; the real message is
    # update.business_message).
    app.add_handler(MessageHandler(filters.Document.ALL & ~filters.UpdateType.BUSINESS_MESSAGE, handle_file))

    # Keeps the business-connection -> owner-chat-id cache warm (see
    # url_checker/message/handler.on_business_connection for why this matters).
    app.add_handler(BusinessConnectionHandler(on_business_connection))

    # "See full details" / "Show less detail" / "Delete" taps on the
    # owner's private business-link notifications.
    app.add_handler(CallbackQueryHandler(handle_business_url_callback, pattern=r"^u:"))

    # Delete/Ignore taps on a direct (non-Business) file-scan result.
    # Explicit pattern so it can never swallow the business-link
    # callbacks above, unlike an unscoped catch-all handler would.
    app.add_handler(CallbackQueryHandler(handle_scan_action_callback, pattern=r"^(delete_|ignore)"))

    # Link checker — text or caption, GROUP/supergroup chat only; silent
    # when no links are found. Plain PRIVATE chat and Business chat are
    # both excluded here on purpose: handle_text (private) and
    # handle_business_message (business) each check and reason over any
    # link themselves, in the same call as the message text/file - this
    # filter firing too would produce a second, uncoordinated reply. Own
    # group so it always runs alongside the text/LLM scan below, even
    # when both match the same photo-with-caption message in a group chat.
    url_filter = (filters.TEXT | filters.CAPTION) & ~filters.COMMAND & ~filters.ChatType.PRIVATE
    app.add_handler(MessageHandler(url_filter, handle_url), group=1)

    # Teammate's text/LLM scan — text or caption, GROUP/supergroup chat and
    # plain PRIVATE chat (private reasons over any link itself - see
    # bot/context_engine.py). Business chat is excluded: it's fully owned
    # by group 3 now. Own group so a document's caption doesn't get
    # shadowed by handle_file's earlier, unconditional match on the same
    # message in group 0.
    app.add_handler(MessageHandler(TEXT_FILTER, handle_text), group=2)

    # Business chat automation: one unified text+link+file check per
    # customer message, privately reported to the business owner. See
    # bot/context_engine.py and handle_business_message's docstring.
    app.add_handler(
        MessageHandler(filters.UpdateType.BUSINESS_MESSAGE, handle_business_message), group=3
    )

    logger.info("Bot is running...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)  # ALL_TYPES so business_message actually gets delivered



if __name__ == "__main__":
    main()
