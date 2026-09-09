import os

from dotenv import load_dotenv

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
SCAN_LOG_DB = os.getenv("SCAN_LOG_DB", "scan_logs.db")

# Supabase Postgres (pgvector) - backs bot/detectors/url/offline/vectors.py's
# brand/phish/seen/scam_pattern similarity store only. Everything else
# (scan logs, domain/cert/VT caches, MinHash page dedup) stays on SQLite.
# Connection string goes through Supabase's Session pooler (port 5432,
# not the Transaction pooler on 6543) - Session mode behaves like a
# direct per-session connection, so it doesn't hit the well-known
# asyncpg/PgBouncer prepared-statement incompatibility Transaction mode
# has (moot for us anyway since this project uses psycopg3, not asyncpg).
SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL")

# Where bot/storage/health_alerts.py sends a message when Gemini/
# VirusTotal/Supabase have failed repeatedly - a Telegram user id or
# chat id (a private chat with an admin, or a small admin group the
# bot is in). None (unset) means alerting is disabled - failures still
# get logged, just no Telegram notification, matching this project's
# existing "degrade gracefully, never crash on missing optional config"
# pattern (e.g. VIRUSTOTAL_API_KEY/GEMINI_API_KEY being optional).
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")

# bge-m3 (Khmer-capable scam-pattern embeddings) - prepared, NOT wired
# into the live query path yet. Production hosting (Daun Penh Data
# Center or equivalent always-on Ollama) hasn't been arranged; this
# defaults to a local dev endpoint and stays OFF unless explicitly
# enabled. See bot/detectors/text/online/bge_m3_embed.py.
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
USE_BGE_M3_EMBEDDINGS = os.getenv("USE_BGE_M3_EMBEDDINGS", "false").lower() == "true"

# bge-m3 runs measurably "hotter" than the hashed scheme - even
# genuinely benign text often scores 0.5-0.67 (confirmed live: a plain
# "hey where are you, waiting at the restaurant" scored 0.593), so
# reusing SCAM_PATTERN_THRESHOLD (tuned for the hashed scheme) here
# would false-positive constantly. This value matches the sandbox
# validation from an earlier session: scam range 0.724-0.861, benign
# range 0.508-0.674 across 54 real test cases - 0.70 sits in the gap.
BGE_M3_PATTERN_THRESHOLD = float(os.getenv("BGE_M3_PATTERN_THRESHOLD", "0.70"))

# Offline scam-message pattern similarity threshold (bot/context_engine/
# context_engine.py's no-Gemini fallback) - calibrated live against real
# examples: a near-verbatim repeat of a known scam script scored 0.686,
# genuinely benign messages topped out at 0.337. Env-overridable since
# re-tuning this (e.g. after adding more seed patterns) is an expected,
# routine change, not a code change.
SCAM_PATTERN_THRESHOLD = float(os.getenv("SCAM_PATTERN_THRESHOLD", "0.5"))

# The Telegram Bot API only ever gives message timestamps in UTC - it has
# no concept of a user's real local timezone at all, so a genuinely
# per-user "UTC + their timezone" display (as literally requested) isn't
# something the Bot API can answer. This is a single project-wide offset
# instead, defaulting to Cambodia's ICT (UTC+7) since this bot's whole
# audience/localization (the km i18n locale) is Cambodia-based - override
# via .env if that's ever wrong for a deployment.
DISPLAY_TIMEZONE_OFFSET_HOURS = int(os.getenv("DISPLAY_TIMEZONE_OFFSET_HOURS", "7"))

SUSPICIOUS_KEYWORDS = (
    "free bitcoin",
    "claim reward",
    "login-verify",
    "account-suspended",
    "bit.ly",
    "tinyurl.com",
)
