import os

from dotenv import load_dotenv

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SCAN_LOG_DB = os.getenv("SCAN_LOG_DB", "scan_logs.db")

SUSPICIOUS_KEYWORDS = (
    "free bitcoin",
    "claim reward",
    "login-verify",
    "account-suspended",
    "bit.ly",
    "tinyurl.com",
)