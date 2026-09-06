"""
tests/test_subscription.py
=============================
Direct tests for the Freemium daily-limit and Live Detect trial logic
in bot/storage/subscription.py. Uses the same isolated-DB pattern as
the rest of the suite (see conftest.py's isolated_scan_log_db fixture,
which this module's SCAN_LOG_DB import already picks up).
"""

from datetime import datetime, timedelta, timezone

from bot.storage import subscription as sub


def test_freemium_file_limit_boundary():
    uid = 1001
    for _ in range(sub.FREEMIUM_DAILY_FILES):
        assert sub.can_scan_file(uid)
        sub.record_file_scan(uid)
    assert not sub.can_scan_file(uid)  # exactly at the limit, not one under


def test_freemium_links_messages_limit_boundary():
    uid = 1002
    for _ in range(sub.FREEMIUM_DAILY_LINKS_MESSAGES):
        assert sub.can_scan_link_or_message(uid)
        sub.record_link_or_message_scan(uid)
    assert not sub.can_scan_link_or_message(uid)


def test_files_and_links_are_independent_counters():
    # Using up the file quota must not affect the links/messages quota
    # and vice versa - they're separate buckets per the plan (3 files +
    # 8 links/messages, not one shared "8 total actions" pool).
    uid = 1003
    for _ in range(sub.FREEMIUM_DAILY_FILES):
        sub.record_file_scan(uid)
    assert not sub.can_scan_file(uid)
    assert sub.can_scan_link_or_message(uid)  # untouched


def test_token_budget_gates_before_the_call_and_records_after():
    uid = 1004
    assert sub.has_token_budget(uid)
    sub.record_token_usage(uid, sub.FREEMIUM_DAILY_TOKENS - 100)
    assert sub.has_token_budget(uid)  # still under
    sub.record_token_usage(uid, 200)  # pushes over
    assert not sub.has_token_budget(uid)


def test_record_token_usage_ignores_non_positive_values():
    uid = 1005
    sub.record_token_usage(uid, 0)
    sub.record_token_usage(uid, -50)
    summary = sub.usage_summary(uid)
    assert summary["tokens_used"] == 0


def test_usage_resets_for_a_different_user():
    # Different users must never share a counter.
    uid_a, uid_b = 1006, 1007
    for _ in range(sub.FREEMIUM_DAILY_FILES):
        sub.record_file_scan(uid_a)
    assert not sub.can_scan_file(uid_a)
    assert sub.can_scan_file(uid_b)


def test_usage_summary_matches_real_recorded_counts():
    uid = 1008
    sub.record_file_scan(uid)
    sub.record_link_or_message_scan(uid)
    sub.record_link_or_message_scan(uid)
    sub.record_token_usage(uid, 500)

    summary = sub.usage_summary(uid)
    assert summary == {
        "files_used": 1, "files_limit": sub.FREEMIUM_DAILY_FILES,
        "links_messages_used": 2, "links_messages_limit": sub.FREEMIUM_DAILY_LINKS_MESSAGES,
        "tokens_used": 500, "tokens_limit": sub.FREEMIUM_DAILY_TOKENS,
    }


def test_usage_rolls_over_on_a_new_day():
    # The daily_usage table is keyed by (user_id, date) - a genuinely
    # new day must get a fresh row, not carry yesterday's counts
    # forward. Verified by directly inserting a row for a past date
    # (not by mocking "now", which would need mocking every call site's
    # own datetime.now() independently) and confirming today's real
    # _get_or_create_today() ignores it entirely.
    uid = 1009
    conn = sub._connect()
    try:
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()
        conn.execute(
            "insert into daily_usage (user_id, usage_date, files_used, links_messages_used, tokens_used) "
            "values (?, ?, ?, ?, ?)",
            (uid, yesterday, sub.FREEMIUM_DAILY_FILES, sub.FREEMIUM_DAILY_LINKS_MESSAGES, sub.FREEMIUM_DAILY_TOKENS),
        )
        conn.commit()
    finally:
        conn.close()

    # Yesterday's row shows the user maxed out - today must be unaffected.
    assert sub.can_scan_file(uid)
    assert sub.can_scan_link_or_message(uid)
    assert sub.has_token_budget(uid)
    assert sub.usage_summary(uid)["files_used"] == 0


def test_file_and_token_limits_are_independent_counters():
    # Exhausting the token budget must not affect the file-scan counter
    # and vice versa - three genuinely separate buckets (3 files + 8
    # links/messages + 20,000 tokens), not one shared pool.
    uid = 1010
    sub.record_token_usage(uid, sub.FREEMIUM_DAILY_TOKENS)
    assert not sub.has_token_budget(uid)
    assert sub.can_scan_file(uid)
    assert sub.can_scan_link_or_message(uid)


def test_live_detect_trial_starts_only_once():
    uid = 2001
    assert sub.live_detect_trial_days_left(uid) == sub.FREEMIUM_TRIAL_DAYS
    assert sub.live_detect_allowed(uid)

    sub.ensure_trial_started(uid)
    days_left_first = sub.live_detect_trial_days_left(uid)

    sub.ensure_trial_started(uid)  # calling again must NOT reset the clock
    assert sub.live_detect_trial_days_left(uid) == days_left_first


def test_live_detect_trial_expires_after_seven_days(monkeypatch):
    uid = 2002
    conn = sub._connect()
    try:
        eight_days_ago = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
        conn.execute(
            "insert into trial_status (user_id, trial_started_at) values (?, ?)",
            (uid, eight_days_ago),
        )
        conn.commit()
    finally:
        conn.close()

    assert sub.live_detect_trial_days_left(uid) == 0
    assert not sub.live_detect_allowed(uid)


def test_live_detect_trial_still_active_on_day_six():
    uid = 2003
    conn = sub._connect()
    try:
        six_days_ago = (datetime.now(timezone.utc) - timedelta(days=6)).isoformat()
        conn.execute(
            "insert into trial_status (user_id, trial_started_at) values (?, ?)",
            (uid, six_days_ago),
        )
        conn.commit()
    finally:
        conn.close()

    assert sub.live_detect_trial_days_left(uid) == 1
    assert sub.live_detect_allowed(uid)


def test_paid_users_get_the_individual_tier_limit_not_the_freemium_one(monkeypatch):
    # "Paid bypasses limits" doesn't mean unlimited - the Individual
    # tier has its own real cap (5 files/day), just a higher one than
    # Freemium's 3. Proves the tier switch actually took effect (used
    # past the Freemium cap) without pretending paid means infinite.
    uid = 3001
    monkeypatch.setattr(sub, "is_paid_user", lambda user_id: True)

    for _ in range(sub.INDIVIDUAL_DAILY_FILES):
        assert sub.can_scan_file(uid)
        sub.record_file_scan(uid)
    assert not sub.can_scan_file(uid)
    assert sub.INDIVIDUAL_DAILY_FILES > sub.FREEMIUM_DAILY_FILES  # sanity: this really is a bypass

    assert sub.live_detect_allowed(uid)  # never started a trial, still allowed - paid tier
