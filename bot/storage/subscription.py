"""
bot/storage/subscription.py
=============================
Freemium tier enforcement: daily file/link-message/token limits, and
the 7-day Live Detect (business-chat automation) trial - plus, since
2026-09-22, the user's chosen language. Backed by Supabase Postgres
(daily_usage, user_state - see supabase/schema.sql), not local SQLite -
Render's free hosting tier wipes the entire filesystem on every deploy/
restart/sleep-wake (confirmed live, 2026-09-22), which used to silently
reset every Business owner's trial clock and every user's quota on each
push. Shares the same pool vectors.py's url_vectors store uses (see
bot/storage/postgres_pool.py) rather than opening a second one against
Supabase's limited connection ceiling.

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

Degradation policy (2026-09-22, matches pipeline.py's _safe_nearest):
every function here catches a Supabase failure, logs it via
health_alerts, and returns a SAFE default rather than raising into the
caller. "Safe" means fail OPEN for anything that gates the feature
itself (can_scan_file/can_scan_link_or_message/live_detect_allowed all
return True on error - this system softly rations a free tier, not
revenue, and blocking a legitimate user over a Supabase hiccup is worse
than one extra free scan slipping through) and fail QUIET for
notifications (should_notify_* return False - a missed one-time notice
is harmless, a wrong one from stale state is not).
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone

from bot.response.verdict_style import format_local_datetime
from bot.storage import health_alerts
from bot.storage.postgres_pool import get_pool

logger = logging.getLogger(__name__)

FREEMIUM_DAILY_FILES = 3
FREEMIUM_DAILY_LINKS_MESSAGES = 8
FREEMIUM_DAILY_TOKENS = 20_000
FREEMIUM_TRIAL_DAYS = 7

# Defined but not enforced - see module docstring.
INDIVIDUAL_DAILY_FILES = 5
INDIVIDUAL_DAILY_LINKS_MESSAGES = 15
INDIVIDUAL_DAILY_TOKENS = 60_000


def _today() -> date:
    return datetime.now(timezone.utc).date()


def next_daily_reset_at() -> datetime:
    """The real UTC instant today's file/link-message/token counters
    reset - always the next UTC midnight, since _today()/usage_date is
    keyed on datetime.now(timezone.utc).date(). A daily_usage row for a
    new date is only ever created lazily (_get_or_create_today), but the
    reset MOMENT itself doesn't depend on that - it's always this
    instant regardless of whether today's row happens to exist yet."""
    tomorrow = datetime.now(timezone.utc).date() + timedelta(days=1)
    return datetime(tomorrow.year, tomorrow.month, tomorrow.day, tzinfo=timezone.utc)


def reset_time_display() -> str:
    """next_daily_reset_at() rendered as a real local date+time, for the
    "your limit will reset at {reset_time}" messages - replacing the old
    bare "tomorrow", which told the user nothing about WHEN. Shares
    verdict_style.format_local_datetime with url_handler.py's business
    header and health_alerts.py's admin-alert timestamp (extracted
    2026-09-16, found by code review, after this exact format existed
    independently in all three places) - one project-wide
    DISPLAY_TIMEZONE_OFFSET_HOURS default (see that constant's own
    docstring for why a true per-user timezone isn't something the Bot
    API can answer)."""
    return format_local_datetime(next_daily_reset_at())


async def _on_supabase_failure(where: str, error: Exception) -> None:
    logger.exception("[subscription] %s failed", where)
    health_alerts.record_failure("Supabase", str(error))
    await health_alerts.maybe_alert("Supabase", str(error))


async def is_paid_user(user_id: int) -> bool:
    """Always False for now - see module docstring."""
    return False


async def _limits_for(user_id: int) -> tuple[int, int, int]:
    """(daily_files, daily_links_messages, daily_tokens) for this user's actual tier."""
    if await is_paid_user(user_id):
        return INDIVIDUAL_DAILY_FILES, INDIVIDUAL_DAILY_LINKS_MESSAGES, INDIVIDUAL_DAILY_TOKENS
    return FREEMIUM_DAILY_FILES, FREEMIUM_DAILY_LINKS_MESSAGES, FREEMIUM_DAILY_TOKENS


async def _get_or_create_today(user_id: int) -> tuple[int, int, int, bool, bool]:
    """(files_used, links_messages_used, tokens_used, file_limit_notified,
    links_messages_limit_notified) for today's row, creating it first if
    this is the user's first call today. One round trip: `on conflict do
    update set user_id = excluded.user_id` is a no-op write that exists
    only so `returning` hands back the existing row on a conflict too -
    `on conflict do nothing` would return nothing at all in that case."""
    pool = await get_pool()
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            insert into daily_usage (user_id, usage_date) values (%s, %s)
            on conflict (user_id, usage_date) do update set user_id = excluded.user_id
            returning files_used, links_messages_used, tokens_used,
                      file_limit_notified, links_messages_limit_notified
            """,
            (user_id, _today()),
        )
        return await cur.fetchone()


async def can_scan_file(user_id: int) -> bool:
    """Check WITHOUT incrementing - callers check before doing the
    expensive work, then call record_file_scan() only once it actually
    ran, mirroring this codebase's existing check-then-act-then-log
    pattern (e.g. log_scan). Fails OPEN (allows the scan) on a Supabase
    outage - see module docstring."""
    try:
        max_files, _, _ = await _limits_for(user_id)
        files_used, _, _, _, _ = await _get_or_create_today(user_id)
        return files_used < max_files
    except Exception as error:                          # noqa: BLE001 - degrade, never block a scan
        await _on_supabase_failure("can_scan_file", error)
        return True


async def record_file_scan(user_id: int) -> None:
    try:
        pool = await get_pool()
        async with pool.connection() as conn:
            await conn.execute(
                """
                insert into daily_usage (user_id, usage_date, files_used) values (%s, %s, 1)
                on conflict (user_id, usage_date) do update
                set files_used = daily_usage.files_used + 1
                """,
                (user_id, _today()),
            )
    except Exception as error:                          # noqa: BLE001 - the scan already happened, never raise here
        await _on_supabase_failure("record_file_scan", error)


async def can_scan_link_or_message(user_id: int) -> bool:
    try:
        _, max_links, _ = await _limits_for(user_id)
        _, links_messages_used, _, _, _ = await _get_or_create_today(user_id)
        return links_messages_used < max_links
    except Exception as error:                          # noqa: BLE001 - degrade, never block a scan
        await _on_supabase_failure("can_scan_link_or_message", error)
        return True


async def record_link_or_message_scan(user_id: int) -> None:
    try:
        pool = await get_pool()
        async with pool.connection() as conn:
            await conn.execute(
                """
                insert into daily_usage (user_id, usage_date, links_messages_used) values (%s, %s, 1)
                on conflict (user_id, usage_date) do update
                set links_messages_used = daily_usage.links_messages_used + 1
                """,
                (user_id, _today()),
            )
    except Exception as error:                          # noqa: BLE001 - the scan already happened, never raise here
        await _on_supabase_failure("record_link_or_message_scan", error)


async def has_token_budget(user_id: int) -> bool:
    """Checked BEFORE calling Gemini, to skip an expensive call
    entirely once the daily budget is gone. A single already-in-flight
    call can still push actual usage slightly over budget (recorded
    afterward via record_token_usage) - same "check before, bill after"
    tradeoff as any simple metering scheme; a mid-generation token cap
    would need streaming, out of scope here. Fails OPEN on a Supabase
    outage - a metering gap must never be why Gemini reasoning gets
    skipped."""
    try:
        _, _, max_tokens = await _limits_for(user_id)
        _, _, tokens_used, _, _ = await _get_or_create_today(user_id)
        return tokens_used < max_tokens
    except Exception as error:                          # noqa: BLE001 - degrade, never block a real Gemini call
        await _on_supabase_failure("has_token_budget", error)
        return True


async def record_token_usage(user_id: int, tokens: int) -> None:
    if tokens <= 0:
        return
    try:
        pool = await get_pool()
        async with pool.connection() as conn:
            await conn.execute(
                """
                insert into daily_usage (user_id, usage_date, tokens_used) values (%s, %s, %s)
                on conflict (user_id, usage_date) do update
                set tokens_used = daily_usage.tokens_used + excluded.tokens_used
                """,
                (user_id, _today(), tokens),
            )
    except Exception as error:                          # noqa: BLE001 - the call already happened, never raise here
        await _on_supabase_failure("record_token_usage", error)


async def should_notify_file_limit(user_id: int) -> bool:
    """True exactly once per day: the first call after can_scan_file()
    turns False for this user flips today's flag and returns True; every
    later call the same day - however many more messages arrive while
    still over quota - returns False, so the caller sends the
    "limit reached" reply only that one time. Only meaningful to call
    once can_scan_file() has already returned False; calling it while
    still under quota just spends the flag for nothing. Fails to False
    (don't notify) on a Supabase outage - a missed notice is harmless.
    """
    try:
        pool = await get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update daily_usage set file_limit_notified = true
                where user_id = %s and usage_date = %s and file_limit_notified = false
                returning user_id
                """,
                (user_id, _today()),
            )
            row = await cur.fetchone()
        return row is not None
    except Exception as error:                          # noqa: BLE001 - a missed one-time notice is harmless
        await _on_supabase_failure("should_notify_file_limit", error)
        return False


async def should_notify_link_limit(user_id: int) -> bool:
    """Same one-notification-per-day contract as should_notify_file_limit,
    for the links/messages counter - shared by every surface that draws
    from it (private DM, group /check, group link checker), so a user
    hitting the limit in one surface doesn't get told again from another
    the same day."""
    try:
        pool = await get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update daily_usage set links_messages_limit_notified = true
                where user_id = %s and usage_date = %s and links_messages_limit_notified = false
                returning user_id
                """,
                (user_id, _today()),
            )
            row = await cur.fetchone()
        return row is not None
    except Exception as error:                          # noqa: BLE001 - a missed one-time notice is harmless
        await _on_supabase_failure("should_notify_link_limit", error)
        return False


async def should_notify_live_detect_ended(user_id: int) -> bool:
    """True exactly once: the first call after live_detect_allowed()
    turns False for this owner flips the flag and returns True; every
    later customer message that arrives while the trial is still over
    returns False, so the owner is told Live Detect stopped working once,
    not on every incoming message. Unlike the two daily counters above,
    nothing resets this today - see ensure_trial_started's comment on
    why that's deliberate, not an oversight. Only meaningful to call
    once live_detect_allowed() has already returned False; ensure_trial_started
    must have run first so the row exists."""
    try:
        pool = await get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update user_state set notified_trial_ended = true
                where user_id = %s and notified_trial_ended = false
                returning user_id
                """,
                (user_id,),
            )
            row = await cur.fetchone()
        return row is not None
    except Exception as error:                          # noqa: BLE001 - a missed one-time notice is harmless
        await _on_supabase_failure("should_notify_live_detect_ended", error)
        return False


async def usage_summary(user_id: int) -> dict:
    """Real numbers for a status reply, not internal-only bookkeeping.
    Degrades to an all-zero-used (limits intact) shape on a Supabase
    outage rather than raising and breaking the /usage reply."""
    try:
        max_files, max_links, max_tokens = await _limits_for(user_id)
        files_used, links_messages_used, tokens_used, _, _ = await _get_or_create_today(user_id)
        return {
            "files_used": files_used, "files_limit": max_files,
            "links_messages_used": links_messages_used, "links_messages_limit": max_links,
            "tokens_used": tokens_used, "tokens_limit": max_tokens,
        }
    except Exception as error:                          # noqa: BLE001 - degrade to a real-limits, zero-used shape
        await _on_supabase_failure("usage_summary", error)
        max_files, max_links, max_tokens = await _limits_for(user_id)
        return {
            "files_used": 0, "files_limit": max_files,
            "links_messages_used": 0, "links_messages_limit": max_links,
            "tokens_used": 0, "tokens_limit": max_tokens,
        }


async def ensure_trial_started(user_id: int) -> None:
    """Idempotent - call every time a business connection is seen.
    trial_started_at is set once and never reset: the coalesce keeps
    whatever was already there (a real prior start date, or a row
    created first by set_stored_lang with trial_started_at still null)
    and only fills it in with `excluded.trial_started_at` the very
    first time a row/value exists for this user - same "first call
    wins" contract the old SQLite `insert or ignore` had, but safe
    against user_state now also being written by the language-
    preference path."""
    try:
        pool = await get_pool()
        async with pool.connection() as conn:
            await conn.execute(
                """
                insert into user_state (user_id, trial_started_at) values (%s, %s)
                on conflict (user_id) do update
                set trial_started_at = coalesce(user_state.trial_started_at, excluded.trial_started_at)
                """,
                (user_id, datetime.now(timezone.utc)),
            )
    except Exception as error:                          # noqa: BLE001 - never block the business-message flow
        await _on_supabase_failure("ensure_trial_started", error)


async def live_detect_trial_days_left(user_id: int) -> int:
    """Days remaining in the 7-day Live Detect trial; FREEMIUM_TRIAL_DAYS
    if the trial has never started yet (nothing consumed until
    ensure_trial_started is actually called), 0 once expired. Also
    returns FREEMIUM_TRIAL_DAYS on a Supabase outage - identical to the
    "never started" default, so a transient failure reads as a fresh
    trial rather than a false "expired"."""
    try:
        pool = await get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                "select trial_started_at from user_state where user_id = %s", (user_id,)
            )
            row = await cur.fetchone()
    except Exception as error:                          # noqa: BLE001 - degrade as "trial not started"
        await _on_supabase_failure("live_detect_trial_days_left", error)
        return FREEMIUM_TRIAL_DAYS
    if row is None or row[0] is None:
        return FREEMIUM_TRIAL_DAYS
    started = row[0]
    elapsed_days = (datetime.now(timezone.utc) - started).days
    return max(FREEMIUM_TRIAL_DAYS - elapsed_days, 0)


async def live_detect_allowed(user_id: int) -> bool:
    if await is_paid_user(user_id):
        return True
    return await live_detect_trial_days_left(user_id) > 0


async def get_stored_lang(user_id: int) -> str | None:
    """The user's last explicitly chosen language, or None if they've
    never picked one (or Supabase is unreachable) - callers fall back to
    DEFAULT_LANG themselves, same contract the old context.user_data.get(
    "lang", DEFAULT_LANG) had. See bot/handlers/text_handler.py's
    get_user_lang, which checks context.user_data first (cheap, correct
    for the rest of the process's life) and only calls this on a cache
    miss (first message after a restart)."""
    try:
        pool = await get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute("select lang from user_state where user_id = %s", (user_id,))
            row = await cur.fetchone()
    except Exception as error:                          # noqa: BLE001 - degrade to "no stored preference"
        await _on_supabase_failure("get_stored_lang", error)
        return None
    return row[0] if row else None


async def set_stored_lang(user_id: int, lang: str) -> None:
    """Only touches the lang/updated_at columns - trial_started_at/
    notified_trial_ended (if already set by ensure_trial_started) are
    left exactly as they were, since they're not in this statement's SET
    clause. Never raises: a failed write here must never block sending
    the "language set" confirmation the caller already committed to."""
    try:
        pool = await get_pool()
        async with pool.connection() as conn:
            await conn.execute(
                """
                insert into user_state (user_id, lang) values (%s, %s)
                on conflict (user_id) do update set lang = excluded.lang, updated_at = now()
                """,
                (user_id, lang),
            )
    except Exception as error:                          # noqa: BLE001 - never block the reply already sent
        await _on_supabase_failure("set_stored_lang", error)
