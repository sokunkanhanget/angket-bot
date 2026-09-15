import os

from dotenv import load_dotenv

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
# Optional, like GEMINI_API_KEY itself - see bot/detectors/text/online/
# gemini_retry.py. Only ever used as a one-shot retry when the primary
# key hits a 429 (quota/rate-limit) specifically, not on other failures.
GEMINI_API_KEY_BACKUP = os.getenv("GEMINI_API_KEY_BACKUP")
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
# genuinely benign text scores in the 0.46-0.72 band, so reusing
# SCAM_PATTERN_THRESHOLD (tuned for the hashed scheme) here would
# false-positive constantly.
#
# Recalibrated against real bge-m3 embeddings (local Ollama, the real
# nearest_scam_pattern_live path) over 37 held-out cases, after Khmer
# scripts were added to SCAM_MESSAGE_PATTERNS:
#
#   scam   (16 cases, Khmer + English)  0.7596 - 0.9733
#   benign (21 cases, Khmer + English)  0.4578 - 0.7155
#   safe threshold window               (0.7155, 0.7596]
#
# Raised from 0.70 to 0.74 because 0.70 produced a real false positive:
# "your salary has been deposited into your account this morning" - a
# genuinely benign bank notification - scored 0.7155 against the
# job_offer seed. That match is on an ENGLISH seed, so it predates the
# Khmer additions; the recalibration is what surfaced it. At 0.74 the
# measured set has zero false positives AND zero false negatives, so
# this removes a bad flag without costing any real detection.
#
# Khmer alone separates more cleanly than the mixed set: scam
# 0.8592-0.9616 against benign 0.4578-0.6846.
BGE_M3_PATTERN_THRESHOLD = float(os.getenv("BGE_M3_PATTERN_THRESHOLD", "0.74"))

# Offline scam-message pattern similarity threshold (bot/context_engine/
# context_engine.py's no-Gemini fallback) - calibrated live against real
# examples: a near-verbatim repeat of a known scam script scored 0.686,
# genuinely benign messages topped out at 0.337. Env-overridable since
# re-tuning this (e.g. after adding more seed patterns) is an expected,
# routine change, not a code change.
#
# Re-verified after Khmer scripts were added to SCAM_MESSAGE_PATTERNS,
# over the same 37 held-out cases. 0.5 still holds and is UNCHANGED:
#
#   Khmer scam   (11 cases)  0.5575 - 0.7134   before Khmer seeds: 0.0556 - 0.1663
#   Khmer benign (15 cases)  0.0938 - 0.2379
#   safe Khmer window        (0.2379, 0.5575]  -> 0.5 sits inside it
#   false positives at 0.5   0 of 21 benign cases, Khmer and English
#
# The "before" row is the whole point: with English seeds only, a Khmer
# scam message scored ~0.06-0.17 here, so it could never reach this
# threshold and contributed nothing at all to the offline signal.
#
# Known, pre-existing and deliberately not chased: this hashed scheme
# still misses some ENGLISH paraphrases (2 of 5 held-out English scams
# scored below 0.5, one as low as 0.3043). That is the documented
# weakness bge-m3 exists to fix, not a regression from the Khmer work -
# English scores are bit-identical before and after it.
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
