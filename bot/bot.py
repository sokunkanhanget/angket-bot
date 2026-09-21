import asyncio
import logging
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Captured before any other project import, so the logged import-time
# phase (below, once logging is configured) covers the REAL cost of
# module-level work in every imported file - notably both Gemini
# clients (context_engine.py, detectors/text/llm.py) are constructed
# at IMPORT time, not inside main(), so that cost is invisible unless
# timed from here.
_import_start = time.perf_counter()

# psycopg's async mode (bot/detectors/url/offline/vectors.py's
# Supabase pgvector pool) can't run on Windows' default ProactorEventLoop
# - must switch BEFORE any event loop is created, which is why this is
# module-level, at the very top, ahead of anything that could start one.
# No-op (and WindowsSelectorEventLoopPolicy doesn't even exist) on
# Linux/Mac, where this was never an issue.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from telegram import BotCommand, BotCommandScopeAllGroupChats, Update
from telegram.ext import (
    Application,
    BusinessConnectionHandler,
    CommandHandler,
    MessageHandler,
    filters,
    TypeHandler,
)

from bot.config.config import GEMINI_API_KEY, SUPABASE_DB_URL, TELEGRAM_BOT_TOKEN, VIRUSTOTAL_API_KEY
from bot.detectors.url.online import network
from bot.handlers.file_handler import handle_file
from bot.handlers.text_handler import COMMAND_KEYS, handle_check, handle_command, handle_text, handle_website, start
from bot.handlers.url_handler import (
    handle_business_message,
    on_business_connection,
)
from bot.storage.scan_log import init_db, init_url_db

# Routing policy for the text/LLM scanner. PRIVATE chat only now - no live
# (unprompted) scanning in GROUP/supergroup chat, per teammate-reported
# 2026-09-19 issue: adding the bot to a group auto-scanned every message,
# which isn't wanted. /check (CommandHandler, ChatType.GROUPS-only, below)
# is the only group-scanning entry point going forward; ~ChatType.CHANNEL
# stays for the same effective_user/None crash class as start/handle_command.
# Group/channel live detection is a deferred future plan, not built.
#
# Named as one shared constant, not re-derived per handler: this exact
# "updated one filter, forgot its sibling" pattern is literally what
# caused the group-auto-scan bug above - TEXT_FILTER got its GROUPS
# exclusion first, and the file-upload handler below kept auto-scanning
# groups for a full extra pass until a teammate caught it. Any future
# chat-type policy change (e.g. if channel support is ever built) now
# only needs to happen here, once, for both handlers that share it.
_PRIVATE_CHAT_ONLY = ~filters.UpdateType.BUSINESS_MESSAGE & ~filters.ChatType.CHANNEL & ~filters.ChatType.GROUPS

TEXT_FILTER = (filters.TEXT | filters.CAPTION) & ~filters.COMMAND & _PRIVATE_CHAT_ONLY

# Direct user spec (2026-09-19): group chat should only ever expose
# /check, /howto, and /policy - /language, /usage, /subscription are all
# private-account concepts (a group has no single "whose plan/language
# is this" the way a private chat does). Module-level (not a local
# inside main()) for the same testability reason as TEXT_FILTER/
# _PRIVATE_CHAT_ONLY above - see test_route.py.
_GROUP_ALLOWED_COMMANDS = {"howto", "policy"}

# Handler groups (PTB runs every group per update, independently; within
# a group, only the FIRST matching handler runs, so anything meant to
# fire alongside another check needs its own group):
#   group 0  — /start menu, file scan (non-Business only) + its
#              Delete/Ignore result buttons, business-connection plumbing
#   group 2  — teammate's text/LLM scan (text or caption). Plain PRIVATE
#              chat only — see below.
#   group 3  — Business chat automation: ONE unified text+link+file check
#              per message (bot/context_engine/context_engine.py + handle_business_message)
#
# No image/photo scanning (e.g. QR decoding) anywhere - text, links, and
# files only, per team decision.
#
# Plain PRIVATE chat: handle_text (group 2) runs there UNCONDITIONALLY and
# internally checks any link itself, reasoning about it together with the
# message text in one Gemini call.
#
# GROUP/supergroup chat: no live/unprompted scanning at all - /check
# (CommandHandler, ChatType.GROUPS-only, below) is the sole entry point,
# reusing the same _run_full_check_and_reply helper handle_text uses. The
# old always-on group auto-scan (a separate handle_url MessageHandler,
# group 1) has been removed entirely, not just filtered inert.
#
# Business chat: fully owned by group 3 now. A Business connection lets a
# user automate their own chat with Angket — every customer message (text,
# link, or file, including a photo's caption) is checked together in one
# call and privately reported to the owner (see
# handlers/url_handler.handle_business_message). Groups 0/1/2's
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

# First real startup-timing phase: everything module-level across every
# file this module (transitively) imports, including both Gemini
# clients being constructed - see _import_start's comment above.
logger.info("[startup] imports finished in %.3fs", time.perf_counter() - _import_start)


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


async def set_bot_commands(application: Application) -> None:
    await application.bot.set_my_commands(
        [BotCommand(command, description) for command, description in (
            ("language", "Switch between English and Khmer"),
            ("howto", "Learn how to use Angket"),
            ("usage", "Check your daily scan"),
            ("policy", "View Angket's policy"),
            ("subscription", "View Premium plans"),
            ("website", "Visit the Angket website"),
        )]
    )
    # Group scope is deliberately a SHORT, DIFFERENT list, not the default
    # list plus /check - direct user spec (2026-09-19): a group member
    # should only ever see /check, /howto, /policy. /language, /usage,
    # /subscription are all private-account concepts with no group
    # equivalent (see the matching CommandHandler filter split above) -
    # showing them in a group's Menu picker would offer a command that
    # silently does nothing when tapped.
    await application.bot.set_my_commands(
        [BotCommand(command, description) for command, description in (
            ("check", "Check a replied-to message, link, or file"),
            ("howto", "Learn how to use Angket"),
            ("policy", "View Angket's policy"),
        )],
        scope=BotCommandScopeAllGroupChats(),
    )


async def close_shared_clients(application: Application) -> None:
    """The link checker's httpx client is now shared across every scan
    instead of built per request (see network._get_client), so it
    outlives any single check and needs releasing on a clean stop rather
    than being torn down by interpreter exit."""
    await network.aclose()


class _HealthCheckHandler(BaseHTTPRequestHandler):
    """Answers any GET with a bare 200 - Render's own health probe and an
    external uptime pinger (UptimeRobot, cron-job.org) both just need a
    response, not real content."""

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's own naming
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):  # noqa: A002 - stdlib's own signature
        pass  # don't spam Render's log with every keepalive ping


def _maybe_start_keepalive_server() -> None:
    """Render's free Web Service tier requires a bound HTTP port and spins
    the process down after 15 minutes with no inbound HTTP traffic - which
    would silently kill Telegram polling too, since it's the same process.
    Binds $PORT (Render sets this; unset everywhere else - local dev, a
    real VM - so this is a no-op there) and answers 200 on any GET so an
    external uptime pinger can keep the process alive. Runs on a daemon
    thread, independent of PTB's own asyncio event loop run_polling()
    owns - simplest way to not fight over which one controls the loop."""
    port = os.getenv("PORT")
    if not port:
        return
    server = ThreadingHTTPServer(("0.0.0.0", int(port)), _HealthCheckHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    logger.info("[startup] keepalive HTTP server listening on port %s", port)


def main():
    main_start = time.perf_counter()
    if not validate_config():
        return

    _maybe_start_keepalive_server()

    step_start = time.perf_counter()
    init_db()
    init_url_db()
    logger.info("[startup] local SQLite tables ready in %.3fs", time.perf_counter() - step_start)

    step_start = time.perf_counter()
    app = (
        Application.builder()
        .token(TELEGRAM_BOT_TOKEN)
        .post_init(set_bot_commands)
        .post_shutdown(close_shared_clients)
        .build()
    )
    logger.info("[startup] Application built in %.3fs", time.perf_counter() - step_start)

    async def _log_every_update(update, context):
        logger.info(
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
    # ~ChatType.CHANNEL on both: start() and handle_command() both call
    # get_user_lang(), which crashes on context.user_data being None -
    # PTB returns None (not {}) whenever the update has no
    # effective_user, which a channel post never has. Channels are
    # explicitly out of scope for this bot (not yet designed for at
    # all, per the group/channel research) - excluded here rather than
    # made to silently "work", matching that decision.
    app.add_handler(CommandHandler("start", start, filters=~filters.ChatType.CHANNEL))
    # /language/usage/subscription now don't respond in groups at all,
    # not just hidden from the Menu picker (see set_bot_commands' matching
    # group-scope trim below) - howto/policy stay reachable everywhere
    # (~ChatType.CHANNEL only, same as before) since they're pure static
    # info, not per-account state. See _GROUP_ALLOWED_COMMANDS' own
    # docstring above for the full rationale.
    for command in COMMAND_KEYS:
        filt = ~filters.ChatType.CHANNEL if command in _GROUP_ALLOWED_COMMANDS else _PRIVATE_CHAT_ONLY
        app.add_handler(CommandHandler(command, handle_command, filters=filt))

    # /website: single external-link button to the real Angket website,
    # direct user spec (2026-09-21). Private-chat only, like /language/
    # usage/subscription - not COMMAND_KEYS/handle_command's static-text
    # dispatch, since its reply is an inline URL button, a different
    # shape from every other menu item's plain translated text.
    app.add_handler(CommandHandler("website", handle_website, filters=_PRIVATE_CHAT_ONLY))

    # /check: on-demand group/supergroup scan, researched and scoped
    # 2026-09-11 (memory: project_group_channel_plan.md), live-tested as
    # a sandbox concept before this port. GROUPS only (not private -
    # private already scans everything unconditionally; not channel -
    # same effective_user/None crash class as start/handle_command
    # above, and channels are still explicitly out of scope).
    app.add_handler(CommandHandler("check", handle_check, filters=filters.ChatType.GROUPS))

    # Business documents are handled by group 3's handle_business_message
    # instead - this used to also match Business messages and crash
    # (update.message is None there; the real message is
    # update.business_message). ~ChatType.CHANNEL for the same reason -
    # handle_file() reads update.message.document unconditionally, and
    # update.message is also None for a channel post (the real object
    # is update.channel_post). _PRIVATE_CHAT_ONLY's GROUPS exclusion
    # matters here too, added 2026-09-19 in the same pass as TEXT_FILTER's
    # own - this handler had NO chat-type restriction at all until then,
    # so a group file upload kept getting auto-scanned even after
    # TEXT_FILTER/url_filter were fixed, until a teammate caught it (see
    # _PRIVATE_CHAT_ONLY's own docstring for why this is now one shared
    # constant instead of two independently-hand-copied filter chains).
    # /check's reply-to-message path already covers a file (replied.
    # document, see handle_check), so groups lose nothing real.
    app.add_handler(MessageHandler(filters.Document.ALL & _PRIVATE_CHAT_ONLY, handle_file))

    # Keeps the business-connection -> owner-chat-id cache warm (see
    # handlers/url_handler.on_business_connection for why this matters).
    app.add_handler(BusinessConnectionHandler(on_business_connection))

    # Teammate's text/LLM scan — text or caption, plain PRIVATE chat only
    # (reasons over any link itself - see bot/context_engine/context_engine.py).
    # GROUP/supergroup and Business are both excluded: groups get no live
    # scanning at all (see /check above and TEXT_FILTER's own comment for
    # why), Business is fully owned by group 3 now. Own group so a
    # document's caption doesn't get shadowed by handle_file's earlier,
    # unconditional match on the same message in group 0.
    app.add_handler(MessageHandler(TEXT_FILTER, handle_text), group=2)

    # Business chat automation: one unified text+link+file check per
    # customer message, privately reported to the business owner. See
    # bot/context_engine/context_engine.py and handle_business_message's docstring.
    app.add_handler(
        MessageHandler(filters.UpdateType.BUSINESS_MESSAGE, handle_business_message), group=3
    )

    logger.info("[startup] main() (SQLite init + Application build + handler "
                "registration) done in %.3fs - NOT counting the import phase "
                "logged above, which already finished before main() was even "
                "called - add both for real cold-start time - polling now...",
                time.perf_counter() - main_start)
    app.run_polling(allowed_updates=Update.ALL_TYPES)  # ALL_TYPES so business_message actually gets delivered



if __name__ == "__main__":
    main()
