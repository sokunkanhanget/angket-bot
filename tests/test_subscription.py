"""
tests/test_subscription.py
=============================
Direct tests for the Freemium daily-limit and Live Detect trial logic
in bot/storage/subscription.py. Backed by Supabase Postgres now
(2026-09-22, see that module's own docstring for why) - the autouse
fake_subscription_store fixture (tests/conftest.py) patches every
public function here onto an in-memory store, so these tests exercise
real _limits_for/_today/tier logic against fake storage instead of a
real Postgres connection - same reasoning conftest.py already used for
url_vectors (bot/detectors/url/offline/vectors.py).

A test that needs to simulate "a row already existed" (e.g. a trial
that started days ago, a daily counter from yesterday) pokes
fake_subscription_store's own daily_usage/user_state dicts directly,
replacing the old raw sub._connect() SQL inserts.
"""

import pytest

from bot.storage import subscription as sub


@pytest.mark.asyncio
async def test_freemium_file_limit_boundary():
    uid = 1001
    for _ in range(sub.FREEMIUM_DAILY_FILES):
        assert await sub.can_scan_file(uid)
        await sub.record_file_scan(uid)
    assert not await sub.can_scan_file(uid)  # exactly at the limit, not one under


@pytest.mark.asyncio
async def test_freemium_links_messages_limit_boundary():
    uid = 1002
    for _ in range(sub.FREEMIUM_DAILY_LINKS_MESSAGES):
        assert await sub.can_scan_link_or_message(uid)
        await sub.record_link_or_message_scan(uid)
    assert not await sub.can_scan_link_or_message(uid)


@pytest.mark.asyncio
async def test_files_and_links_are_independent_counters():
    # Using up the file quota must not affect the links/messages quota
    # and vice versa - they're separate buckets per the plan (3 files +
    # 8 links/messages, not one shared "8 total actions" pool).
    uid = 1003
    for _ in range(sub.FREEMIUM_DAILY_FILES):
        await sub.record_file_scan(uid)
    assert not await sub.can_scan_file(uid)
    assert await sub.can_scan_link_or_message(uid)  # untouched


@pytest.mark.asyncio
async def test_token_budget_gates_before_the_call_and_records_after():
    uid = 1004
    assert await sub.has_token_budget(uid)
    await sub.record_token_usage(uid, sub.FREEMIUM_DAILY_TOKENS - 100)
    assert await sub.has_token_budget(uid)  # still under
    await sub.record_token_usage(uid, 200)  # pushes over
    assert not await sub.has_token_budget(uid)


@pytest.mark.asyncio
async def test_record_token_usage_ignores_non_positive_values():
    uid = 1005
    await sub.record_token_usage(uid, 0)
    await sub.record_token_usage(uid, -50)
    summary = await sub.usage_summary(uid)
    assert summary["tokens_used"] == 0


@pytest.mark.asyncio
async def test_usage_resets_for_a_different_user():
    # Different users must never share a counter.
    uid_a, uid_b = 1006, 1007
    for _ in range(sub.FREEMIUM_DAILY_FILES):
        await sub.record_file_scan(uid_a)
    assert not await sub.can_scan_file(uid_a)
    assert await sub.can_scan_file(uid_b)


@pytest.mark.asyncio
async def test_usage_summary_matches_real_recorded_counts():
    uid = 1008
    await sub.record_file_scan(uid)
    await sub.record_link_or_message_scan(uid)
    await sub.record_link_or_message_scan(uid)
    await sub.record_token_usage(uid, 500)

    summary = await sub.usage_summary(uid)
    assert summary == {
        "files_used": 1, "files_limit": sub.FREEMIUM_DAILY_FILES,
        "links_messages_used": 2, "links_messages_limit": sub.FREEMIUM_DAILY_LINKS_MESSAGES,
        "tokens_used": 500, "tokens_limit": sub.FREEMIUM_DAILY_TOKENS,
    }


@pytest.mark.asyncio
async def test_usage_rolls_over_on_a_new_day(fake_subscription_store):
    # daily_usage is keyed by (user_id, date) - a genuinely new day must
    # get a fresh row, not carry yesterday's counts forward. Verified by
    # directly seeding the fake store's own dict for a past date (not by
    # mocking "now", which would need mocking every call site's own
    # datetime.now() independently) and confirming today's real
    # _get_or_create_today-equivalent ignores it entirely.
    from datetime import timedelta

    uid = 1009
    yesterday = sub._today() - timedelta(days=1)
    fake_subscription_store.daily_usage[(uid, yesterday)] = {
        "files_used": sub.FREEMIUM_DAILY_FILES,
        "links_messages_used": sub.FREEMIUM_DAILY_LINKS_MESSAGES,
        "tokens_used": sub.FREEMIUM_DAILY_TOKENS,
        "file_limit_notified": False, "links_messages_limit_notified": False,
    }

    # Yesterday's row shows the user maxed out - today must be unaffected.
    assert await sub.can_scan_file(uid)
    assert await sub.can_scan_link_or_message(uid)
    assert await sub.has_token_budget(uid)
    assert (await sub.usage_summary(uid))["files_used"] == 0


@pytest.mark.asyncio
async def test_file_and_token_limits_are_independent_counters():
    # Exhausting the token budget must not affect the file-scan counter
    # and vice versa - three genuinely separate buckets (3 files + 8
    # links/messages + 20,000 tokens), not one shared pool.
    uid = 1010
    await sub.record_token_usage(uid, sub.FREEMIUM_DAILY_TOKENS)
    assert not await sub.has_token_budget(uid)
    assert await sub.can_scan_file(uid)
    assert await sub.can_scan_link_or_message(uid)


@pytest.mark.asyncio
async def test_live_detect_trial_starts_only_once():
    uid = 2001
    assert await sub.live_detect_trial_days_left(uid) == sub.FREEMIUM_TRIAL_DAYS
    assert await sub.live_detect_allowed(uid)

    await sub.ensure_trial_started(uid)
    days_left_first = await sub.live_detect_trial_days_left(uid)

    await sub.ensure_trial_started(uid)  # calling again must NOT reset the clock
    assert await sub.live_detect_trial_days_left(uid) == days_left_first


@pytest.mark.asyncio
async def test_live_detect_trial_expires_after_seven_days(fake_subscription_store):
    from datetime import datetime, timedelta, timezone

    uid = 2002
    fake_subscription_store.user_state[uid] = {
        "trial_started_at": datetime.now(timezone.utc) - timedelta(days=8),
        "notified_trial_ended": False, "lang": None,
    }

    assert await sub.live_detect_trial_days_left(uid) == 0
    assert not await sub.live_detect_allowed(uid)


@pytest.mark.asyncio
async def test_live_detect_trial_still_active_on_day_six(fake_subscription_store):
    from datetime import datetime, timedelta, timezone

    uid = 2003
    fake_subscription_store.user_state[uid] = {
        "trial_started_at": datetime.now(timezone.utc) - timedelta(days=6),
        "notified_trial_ended": False, "lang": None,
    }

    assert await sub.live_detect_trial_days_left(uid) == 1
    assert await sub.live_detect_allowed(uid)


@pytest.mark.asyncio
async def test_paid_users_get_the_individual_tier_limit_not_the_freemium_one(monkeypatch):
    # "Paid bypasses limits" doesn't mean unlimited - the Individual
    # tier has its own real cap (5 files/day), just a higher one than
    # Freemium's 3. Proves the tier switch actually took effect (used
    # past the Freemium cap) without pretending paid means infinite.
    uid = 3001

    async def _fake_is_paid_user(user_id):
        return True

    monkeypatch.setattr(sub, "is_paid_user", _fake_is_paid_user)

    for _ in range(sub.INDIVIDUAL_DAILY_FILES):
        assert await sub.can_scan_file(uid)
        await sub.record_file_scan(uid)
    assert not await sub.can_scan_file(uid)
    assert sub.INDIVIDUAL_DAILY_FILES > sub.FREEMIUM_DAILY_FILES  # sanity: this really is a bypass

    assert await sub.live_detect_allowed(uid)  # never started a trial, still allowed - paid tier


# --- Notify-once (2026-09-15 direct user spec) --------------------------
# Tell the user the quota/trial ran out ONCE, not on every message they
# send while still over it.

@pytest.mark.asyncio
async def test_should_notify_file_limit_is_true_once_then_false():
    uid = 4001
    for _ in range(sub.FREEMIUM_DAILY_FILES):
        await sub.record_file_scan(uid)
    assert not await sub.can_scan_file(uid)

    assert await sub.should_notify_file_limit(uid) is True
    assert await sub.should_notify_file_limit(uid) is False
    assert await sub.should_notify_file_limit(uid) is False  # still False, not flaky


@pytest.mark.asyncio
async def test_should_notify_link_limit_is_true_once_then_false():
    uid = 4002
    for _ in range(sub.FREEMIUM_DAILY_LINKS_MESSAGES):
        await sub.record_link_or_message_scan(uid)
    assert not await sub.can_scan_link_or_message(uid)

    assert await sub.should_notify_link_limit(uid) is True
    assert await sub.should_notify_link_limit(uid) is False


@pytest.mark.asyncio
async def test_file_and_link_notify_flags_are_independent():
    uid = 4003
    for _ in range(sub.FREEMIUM_DAILY_FILES):
        await sub.record_file_scan(uid)
    for _ in range(sub.FREEMIUM_DAILY_LINKS_MESSAGES):
        await sub.record_link_or_message_scan(uid)

    assert await sub.should_notify_file_limit(uid) is True
    # The file flag being spent must not affect the separate link flag.
    assert await sub.should_notify_link_limit(uid) is True
    assert await sub.should_notify_file_limit(uid) is False
    assert await sub.should_notify_link_limit(uid) is False


@pytest.mark.asyncio
async def test_notify_flags_are_independent_per_user():
    uid_a, uid_b = 4004, 4005
    for uid in (uid_a, uid_b):
        for _ in range(sub.FREEMIUM_DAILY_FILES):
            await sub.record_file_scan(uid)

    assert await sub.should_notify_file_limit(uid_a) is True
    assert await sub.should_notify_file_limit(uid_a) is False
    # A different user must still get their own first notification.
    assert await sub.should_notify_file_limit(uid_b) is True


@pytest.mark.asyncio
async def test_notify_flags_reset_on_a_new_day(fake_subscription_store):
    # Matches the "resets tomorrow" wording already in the user-facing
    # message - notified-today must not suppress notified-tomorrow.
    from datetime import timedelta

    uid = 4006
    yesterday = sub._today() - timedelta(days=1)
    fake_subscription_store.daily_usage[(uid, yesterday)] = {
        "files_used": sub.FREEMIUM_DAILY_FILES, "links_messages_used": sub.FREEMIUM_DAILY_LINKS_MESSAGES,
        "tokens_used": 0, "file_limit_notified": True, "links_messages_limit_notified": True,
    }

    # Yesterday's row was already notified - today's fresh row must not
    # inherit that.
    assert await sub.should_notify_file_limit(uid) is True
    assert await sub.should_notify_link_limit(uid) is True


@pytest.mark.asyncio
async def test_should_notify_live_detect_ended_is_true_once_then_false(fake_subscription_store):
    from datetime import datetime, timedelta, timezone

    uid = 4007
    fake_subscription_store.user_state[uid] = {
        "trial_started_at": datetime.now(timezone.utc) - timedelta(days=8),
        "notified_trial_ended": False, "lang": None,
    }
    assert not await sub.live_detect_allowed(uid)

    assert await sub.should_notify_live_detect_ended(uid) is True
    assert await sub.should_notify_live_detect_ended(uid) is False


@pytest.mark.asyncio
async def test_should_notify_live_detect_ended_false_with_no_trial_row():
    # ensure_trial_started is supposed to run first in the real call
    # site; calling this without a row must fail safe (no crash, no
    # spurious True) rather than assume "never notified" means "notify".
    uid = 4008
    assert await sub.should_notify_live_detect_ended(uid) is False


@pytest.mark.asyncio
async def test_live_detect_notify_flag_is_independent_per_user(fake_subscription_store):
    from datetime import datetime, timedelta, timezone

    uid_a, uid_b = 4009, 4010
    eight_days_ago = datetime.now(timezone.utc) - timedelta(days=8)
    for uid in (uid_a, uid_b):
        fake_subscription_store.user_state[uid] = {
            "trial_started_at": eight_days_ago, "notified_trial_ended": False, "lang": None,
        }

    assert await sub.should_notify_live_detect_ended(uid_a) is True
    assert await sub.should_notify_live_detect_ended(uid_a) is False
    assert await sub.should_notify_live_detect_ended(uid_b) is True


# --- reset_time_display / next_daily_reset_at (2026-09-16 direct user
# spec: tell the user a real reset TIME, not just "tomorrow") ----------

def test_next_daily_reset_at_is_always_the_next_utc_midnight():
    from datetime import datetime, timedelta, timezone

    reset_at = sub.next_daily_reset_at()

    assert reset_at.tzinfo is timezone.utc
    assert reset_at.hour == 0 and reset_at.minute == 0 and reset_at.second == 0
    tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).date()
    assert reset_at.date() == tomorrow


def test_reset_time_display_reflects_the_display_timezone_offset(monkeypatch):
    # DISPLAY_TIMEZONE_OFFSET_HOURS is read via
    # verdict_style.format_local_datetime now (shared, 2026-09-16), not
    # a local name in subscription.py's own namespace.
    from datetime import timedelta

    from bot.response import verdict_style
    monkeypatch.setattr(verdict_style, "DISPLAY_TIMEZONE_OFFSET_HOURS", 7)
    reset_at = sub.next_daily_reset_at()

    display = sub.reset_time_display()

    local_dt = reset_at + timedelta(hours=7)
    assert local_dt.strftime("%d %b %Y, %I:%M %p") in display
    assert "(UTC+7)" in display


def test_reset_time_display_is_a_real_time_not_the_word_tomorrow():
    display = sub.reset_time_display()

    assert "tomorrow" not in display.lower()
    assert ":" in display  # a real clock time is present


def test_reset_time_display_handles_a_negative_offset(monkeypatch):
    from bot.response import verdict_style
    monkeypatch.setattr(verdict_style, "DISPLAY_TIMEZONE_OFFSET_HOURS", -5)
    display = sub.reset_time_display()

    assert "(UTC-5)" in display


def test_daily_file_limit_reached_message_shows_a_real_reset_time():
    from bot.response.buttons import t

    message = t("en", "daily_file_limit_reached").format(
        limit=sub.FREEMIUM_DAILY_FILES, reset_time=sub.reset_time_display(),
    )

    assert "tomorrow" not in message.lower()
    assert sub.reset_time_display() in message


def test_daily_scan_limit_reached_message_shows_a_real_reset_time_in_khmer():
    from bot.response.buttons import t

    message = t("km", "daily_scan_limit_reached").format(
        limit=sub.FREEMIUM_DAILY_LINKS_MESSAGES, reset_time=sub.reset_time_display(),
    )

    assert "ថ្ងៃស្អែក" not in message  # the old "tomorrow" wording, removed
    assert sub.reset_time_display() in message


# --- Language preference (2026-09-22: moved off pure in-memory
# context.user_data onto Supabase user_state.lang) -----------------------

@pytest.mark.asyncio
async def test_stored_lang_defaults_to_none_when_never_set():
    assert await sub.get_stored_lang(5001) is None


@pytest.mark.asyncio
async def test_set_stored_lang_round_trips():
    uid = 5002
    await sub.set_stored_lang(uid, "km")
    assert await sub.get_stored_lang(uid) == "km"


@pytest.mark.asyncio
async def test_set_stored_lang_does_not_disturb_trial_state():
    # user_state holds both trial + lang now (one row per user) - setting
    # lang must never clobber an already-started trial, and vice versa.
    uid = 5003
    await sub.ensure_trial_started(uid)
    days_left_before = await sub.live_detect_trial_days_left(uid)

    await sub.set_stored_lang(uid, "en")

    assert await sub.live_detect_trial_days_left(uid) == days_left_before
    assert await sub.get_stored_lang(uid) == "en"


@pytest.mark.asyncio
async def test_ensure_trial_started_does_not_disturb_an_already_set_lang():
    # The reverse order: lang set first (e.g. a private-chat /start
    # before this user ever becomes a Business owner), trial started
    # later - the lang must survive.
    uid = 5004
    await sub.set_stored_lang(uid, "km")

    await sub.ensure_trial_started(uid)

    assert await sub.get_stored_lang(uid) == "km"
    assert await sub.live_detect_trial_days_left(uid) == sub.FREEMIUM_TRIAL_DAYS
