from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    MessageHandler,
    filters,
)

from bot.analysis.utils import init_db
from bot.config import TELEGRAM_BOT_TOKEN, VIRUSTOTAL_API_KEY
from bot.handlers.file_handler import handle_button_click, handle_file
from bot.handlers.text_handler import (
    handle_language_selection,
    handle_text,
    start,
)


def main():
    if not TELEGRAM_BOT_TOKEN or not VIRUSTOTAL_API_KEY:
        print("Error: Missing TELEGRAM_BOT_TOKEN or VIRUSTOTAL_API_KEY in .env file.")
        return

    init_db()
    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    # Commands & Messages
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    # Callback Query Handlers
    app.add_handler(CallbackQueryHandler(handle_language_selection, pattern="^lang_"))
    app.add_handler(CallbackQueryHandler(handle_button_click))

    print("🤖 Bot is running with Auto-Translation & Language selection...")
    app.run_polling()


if __name__ == "__main__":
    main()