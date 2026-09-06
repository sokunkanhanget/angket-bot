"""
bot/storage/subscription.py
=============================
Freemium tier enforcement: daily file/link-message/token limits, and
the 7-day Live Detect (business-chat automation) trial. Local SQLite,
same shared scan_logs.db file as every other cache/log (WAL-enabled -
see scan_log.py's init_db()) - this is per-user metering state, not
something needing Supabase's similarity search.

Individual ($3.99/mo) tier limits are defined here per the team's
plan, but NOT enforced anywhere yet - no real payment system exists in
production (the KHQR/Stars prototypes are still sandbox-only in
next-gen-test/concepts/). is_paid_user() always returns False for now;
every real caller already goes through it rather than assuming
Freemium, so wiring in a real subscription lookup later is a one-
function change, not a rewrite.

NOTE for whoever wires up payments for real: VirusTotal's free tier
does not permit commercial use (flagged this session) - charging for
the Individual tier while still on the VT free API is a real
compliance question for the team/mentor, not something this module
can resolve.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from bot.config import SCAN_LOG_DB

# --- Tier limits, per the team's plan ------------------------------------

FREEMIUM_DAILY_FILES = 3
FREEMIUM_DAILY_LINKS_MESSAGES = 8
FREEMIUM_DAILY_TOKENS = 20_000
FREEMIUM_TRIAL_DAYS = 7

# Defined but not enforced - see module docstring.
INDIVIDUAL_DAILY_FILES = 5
INDIVIDUAL_DAILY_LINKS_MESSAGES = 15
INDIVIDUAL_DAILY_TOKENS = 60_000


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(SCAN_LOG_DB)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        create table if not exists daily_usage(
            user_id integer not null,
            usage_date text not null,
            files_used integer not null default 0,
            links_messages_used integer not null default 0,
            tokens_used integer not null default 0,
            primary key (user_id, usage_date)
        )
        """
    )
    conn.execute(
        """
        create table if not exists trial_status(
            user_id integer primary key,
            trial_started_at text not null
        )
        """
    )
    conn.row_factory = sqlite3.Row
    return conn


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def is_paid_user(user_id: int) -> bool:
    """Always False for now - see module docstring."""
    return False


def _limits_for(user_id: int) -> tuple[int, int, int]:
    """(daily_files, daily_links_messages, daily_tokens) for this user's actual tier."""
    if is_paid_user(user_id):
        return INDIVIDUAL_DAILY_FILES, INDIVIDUAL_DAILY_LINKS_MESSAGES, INDIVIDUAL_DAILY_TOKENS
    return FREEMIUM_DAILY_FILES, FREEMIUM_DAILY_LINKS_MESSAGES, FREEMIUM_DAILY_TOKENS


def _get_or_create_today(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row:
    today = _today()
    conn.execute(
        "insert or ignore into daily_usage (user_id, usage_date) values (?, ?)",
        (user_id, today),
    )
    return conn.execute(
        "select * from daily_usage where user_id = ? and usage_date = ?",
        (user_id, today),
    ).fetchone()


def can_scan_file(user_id: int) -> bool:
    """Check WITHOUT incrementing - callers check before doing the
    expensive work, then call record_file_scan() only once it actually
    ran, mirroring this codebase's existing check-then-act-then-log
    pattern (e.g. log_scan)."""
    max_files, _, _ = _limits_for(user_id)
    conn = _connect()
    try:
        row = _get_or_create_today(conn, user_id)
        conn.commit()
        return row["files_used"] < max_files
    finally:
        conn.close()


def record_file_scan(user_id: int) -> None:
    conn = _connect()
    try:
        _get_or_create_today(conn, user_id)
        conn.execute(
            "update daily_usage set files_used = files_used + 1 where user_id = ? and usage_date = ?",
            (user_id, _today()),
        )
        conn.commit()
    finally:
        conn.close()


def can_scan_link_or_message(user_id: int) -> bool:
    _, max_links, _ = _limits_for(user_id)
    conn = _connect()
    try:
        row = _get_or_create_today(conn, user_id)
        conn.commit()
        return row["links_messages_used"] < max_links
    finally:
        conn.close()


def record_link_or_message_scan(user_id: int) -> None:
    conn = _connect()
    try:
        _get_or_create_today(conn, user_id)
        conn.execute(
            "update daily_usage set links_messages_used = links_messages_used + 1 "
            "where user_id = ? and usage_date = ?",
            (user_id, _today()),
        )
        conn.commit()
    finally:
        conn.close()


def has_token_budget(user_id: int) -> bool:
    """Checked BEFORE calling Gemini, to skip an expensive call
    entirely once the daily budget is gone. A single already-in-flight
    call can still push actual usage slightly over budget (recorded
    afterward via record_token_usage) - same "check before, bill after"
    tradeoff as any simple metering scheme; a mid-generation token cap
    would need streaming, out of scope here."""
    _, _, max_tokens = _limits_for(user_id)
    conn = _connect()
    try:
        row = _get_or_create_today(conn, user_id)
        conn.commit()
        return row["tokens_used"] < max_tokens
    finally:
        conn.close()


def record_token_usage(user_id: int, tokens: int) -> None:
    if tokens <= 0:
        return
    conn = _connect()
    try:
        _get_or_create_today(conn, user_id)
        conn.execute(
            "update daily_usage set tokens_used = tokens_used + ? where user_id = ? and usage_date = ?",
            (tokens, user_id, _today()),
        )
        conn.commit()
    finally:
        conn.close()


def usage_summary(user_id: int) -> dict:
    """Real numbers for a status reply, not internal-only bookkeeping."""
    max_files, max_links, max_tokens = _limits_for(user_id)
    conn = _connect()
    try:
        row = _get_or_create_today(conn, user_id)
        conn.commit()
        return {
            "files_used": row["files_used"], "files_limit": max_files,
            "links_messages_used": row["links_messages_used"], "links_messages_limit": max_links,
            "tokens_used": row["tokens_used"], "tokens_limit": max_tokens,
        }
    finally:
        conn.close()


# --- 7-day Live Detect trial (business-chat automation) ------------------

def ensure_trial_started(user_id: int) -> None:
    """Idempotent - call every time a business connection is seen;
    'insert or ignore' means only the FIRST call actually records
    anything, so the trial clock starts once and never resets."""
    conn = _connect()
    try:
        conn.execute(
            "insert or ignore into trial_status (user_id, trial_started_at) values (?, ?)",
            (user_id, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def live_detect_trial_days_left(user_id: int) -> int:
    """Days remaining in the 7-day Live Detect trial; FREEMIUM_TRIAL_DAYS
    if the trial has never started yet (nothing consumed until
    ensure_trial_started is actually called), 0 once expired."""
    conn = _connect()
    try:
        row = conn.execute(
            "select trial_started_at from trial_status where user_id = ?", (user_id,)
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return FREEMIUM_TRIAL_DAYS
    started = datetime.fromisoformat(row["trial_started_at"])
    elapsed_days = (datetime.now(timezone.utc) - started).days
    return max(FREEMIUM_TRIAL_DAYS - elapsed_days, 0)


def live_detect_allowed(user_id: int) -> bool:
    if is_paid_user(user_id):
        return True
    return live_detect_trial_days_left(user_id) > 0
