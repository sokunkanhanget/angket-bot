import os

from dotenv import load_dotenv

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
SCAN_LOG_DB = os.getenv("SCAN_LOG_DB", "scan_logs.db")

# Supabase Postgres (pgvector) - backs bot/url_checker/features/offline/vectors.py's
# brand/phish/seen/scam_pattern similarity store only. Everything else
# (scan logs, domain/cert/VT caches, MinHash page dedup) stays on SQLite.
# Connection string goes through Supabase's Session pooler (port 5432,
# not the Transaction pooler on 6543) - Session mode behaves like a
# direct per-session connection, so it doesn't hit the well-known
# asyncpg/PgBouncer prepared-statement incompatibility Transaction mode
# has (moot for us anyway since this project uses psycopg3, not asyncpg).
SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL")

# Offline scam-message pattern similarity threshold (context_engine.py's
# no-Gemini fallback) - calibrated live against real examples: a
# near-verbatim repeat of a known scam script scored 0.686, genuinely
# benign messages topped out at 0.337. Env-overridable since re-tuning
# this (e.g. after adding more seed patterns) is an expected, routine
# change, not a code change.
SCAM_PATTERN_THRESHOLD = float(os.getenv("SCAM_PATTERN_THRESHOLD", "0.5"))

SUSPICIOUS_KEYWORDS = (
    "free bitcoin",
    "claim reward",
    "login-verify",
    "account-suspended",
    "bit.ly",
    "tinyurl.com",
)