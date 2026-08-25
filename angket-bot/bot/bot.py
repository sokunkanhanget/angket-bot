from telegram.ext import Application, CommandHandler, MessageHandler, filters

from bot.analysis.utils import init_db
from bot.config import TELEGRAM_BOT_TOKEN, VIRUSTOTAL_API_KEY
from bot.handlers.file_handler import handle_file
from bot.handlers.text_handler import handle_text, start


def main():
    if not TELEGRAM_BOT_TOKEN or not VIRUSTOTAL_API_KEY:
        print("Error: Missing TELEGRAM_BOT_TOKEN or VIRUSTOTAL_API_KEY in .env file.")
        return

    init_db()
    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    print("🤖 Bot is running...")
    app.run_polling()


if __name__ == "__main__":
    main()