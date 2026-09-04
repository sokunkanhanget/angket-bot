"""
tests/test_cert_info.py
=========================
score_cert_age and the SQLite cache were previously only ever
exercised via wholesale monkeypatching of cert_issued_days_ago in
tests/test_link_checker.py - the real scoring-tier arithmetic and
cache-hit/miss/expiry logic never actually ran under test. This file
tests those directly.
"""

import sqlite3

import pytest

from bot.detectors.url.online import cert_info


@pytest.fixture(autouse=True)
def _tmp_scan_db(tmp_path, monkeypatch):
    monkeypatch.setattr(cert_info, "SCAN_LOG_DB", str(tmp_path / "test_scan.db"))


# --- score_cert_age boundaries ---------------------------------------------

def test_score_cert_age_none_for_unknown_age():
    assert cert_info.score_cert_age(None) is None


@pytest.mark.parametrize("age,expected_points", [(0, 20), (6, 20), (7, 10), (29, 10)])
def test_score_cert_age_tier_boundaries(age, expected_points):
    result = cert_info.score_cert_age(age)
    assert result is not None
    assert result[0] == expected_points


def test_score_cert_age_no_score_at_or_past_30_days():
    assert cert_info.score_cert_age(30) is None
    assert cert_info.score_cert_age(365) is None


# --- _parse_cert_date malformed input ---------------------------------------

def test_parse_cert_date_handles_wellformed_input():
    assert cert_info._parse_cert_date("Jan  1 00:00:00 2024 GMT") is not None


@pytest.mark.parametrize("raw", ["", "not a date", "2024-01-01", "Jan 1 2024"])
def test_parse_cert_date_returns_none_for_malformed_input(raw):
    # Must degrade to None, never raise - a malformed date string from
    # a misbehaving/malicious server must not crash the whole scan.
    assert cert_info._parse_cert_date(raw) is None


# --- cache hit / miss / expiry -----------------------------------------------

def test_cache_get_reports_not_cached_when_nothing_stored():
    was_cached, value = cert_info._cache_get("never-looked-up.example")
    assert was_cached is False
    assert value is None


def test_cache_put_then_get_round_trips_a_real_value():
    cert_info._cache_put("known-host.example", "2024-01-01T00:00:00+00:00")
    was_cached, value = cert_info._cache_get("known-host.example")
    assert was_cached is True
    assert value == "2024-01-01T00:00:00+00:00"


def test_cache_put_then_get_round_trips_a_negative_result():
    # Regression: a cached "no cert data" (None) result used to be
    # indistinguishable from "never looked up" (_cache_get returned
    # None either way), silently defeating the cache for the miss case
    # and forcing a real TLS handshake retry on every subsequent scan
    # of a host with no cert data. was_cached must be True here even
    # though the cached value itself is None.
    cert_info._cache_put("no-cert-host.example", None)
    was_cached, value = cert_info._cache_get("no-cert-host.example")
    assert was_cached is True
    assert value is None


def test_cache_get_expires_after_ttl(monkeypatch):
    cert_info._cache_put("stale-host.example", "2024-01-01T00:00:00+00:00")

    real_time = cert_info.time.time

    def fake_time():
        return real_time() + cert_info.CACHE_TTL_SECONDS + 1

    monkeypatch.setattr(cert_info.time, "time", fake_time)

    was_cached, value = cert_info._cache_get("stale-host.example")
    assert was_cached is False
    assert value is None


@pytest.mark.asyncio
async def test_cert_issued_days_ago_does_not_re_handshake_on_a_cached_negative_result(monkeypatch):
    # End-to-end version of the cache-the-miss regression above: once a
    # host's "no cert" result is cached, a second call must NOT attempt
    # another real TLS handshake at all.
    handshake_calls = {"n": 0}

    def spy_get_cert_sync(host, port=443):
        handshake_calls["n"] += 1
        return None

    monkeypatch.setattr(cert_info, "_get_cert_sync", spy_get_cert_sync)

    first = await cert_info.cert_issued_days_ago("unreachable-host.example")
    second = await cert_info.cert_issued_days_ago("unreachable-host.example")

    assert first is None
    assert second is None
    assert handshake_calls["n"] == 1  # only the FIRST call should hit the network


def test_connect_creates_the_table_idempotently(tmp_path, monkeypatch):
    db_path = str(tmp_path / "idempotent.db")
    monkeypatch.setattr(cert_info, "SCAN_LOG_DB", db_path)

    cert_info._connect().close()
    cert_info._connect().close()  # must not raise on a pre-existing table

    conn = sqlite3.connect(db_path)
    tables = conn.execute("select name from sqlite_master where type='table'").fetchall()
    conn.close()
    assert ("cert_info",) in tables
