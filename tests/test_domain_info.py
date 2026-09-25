"""
tests/test_domain_info.py
============================
score_domain_age and the RDAP cache were previously only ever exercised
via wholesale monkeypatching of domain_age_days in
tests/test_link_checker.py - the real scoring-tier arithmetic and
cache-hit/miss/expiry/RDAP-parsing logic never actually ran under test.
This file tests those directly.
"""

import sqlite3
import time

import httpx
import pytest

from bot.detectors.url.online import domain_info
from bot.storage import sqlite_pool


@pytest.fixture(autouse=True)
def _tmp_scan_db(tmp_path, monkeypatch):
    monkeypatch.setattr(domain_info, "SCAN_LOG_DB", str(tmp_path / "test_scan.db"))


# --- score_domain_age boundaries --------------------------------------------

def test_score_domain_age_none_for_unknown_age():
    assert domain_info.score_domain_age(None) is None


@pytest.mark.parametrize("age,expected_points", [
    (0, 35), (29, 35),
    (30, 20), (89, 20),
    (90, 10), (364, 10),
])
def test_score_domain_age_tier_boundaries(age, expected_points):
    result = domain_info.score_domain_age(age)
    assert result is not None
    assert result[0] == expected_points


def test_score_domain_age_no_score_at_or_past_365_days():
    assert domain_info.score_domain_age(365) is None
    assert domain_info.score_domain_age(5000) is None


# --- _parse_rdap_date malformed input ----------------------------------------

def test_parse_rdap_date_handles_wellformed_input_with_fractional_seconds():
    assert domain_info._parse_rdap_date("2020-05-14T12:34:56.789Z") == "2020-05-14"


def test_parse_rdap_date_handles_wellformed_input_without_fractional_seconds():
    assert domain_info._parse_rdap_date("2020-05-14T12:34:56Z") == "2020-05-14"


@pytest.mark.parametrize("raw", ["", "not a date", "14/05/2020", "yesterday"])
def test_parse_rdap_date_returns_none_for_malformed_input(raw):
    # Must degrade to None, never raise - a malformed date from a
    # misbehaving RDAP server must not crash the whole scan.
    assert domain_info._parse_rdap_date(raw) is None


# --- cache hit / miss / expiry (registration lookup) -------------------------

def test_cache_get_returns_none_when_nothing_stored():
    assert domain_info._cache_get("never-looked-up.example") is None


def test_cache_put_then_get_round_trips_a_real_value():
    domain_info._cache_put("known-host.example", "2020-01-01", "Some Registrar")
    assert domain_info._cache_get("known-host.example") == ("2020-01-01", "Some Registrar")


def test_cache_put_then_get_round_trips_a_negative_result():
    # fetch_registration explicitly caches a 404 (RDAP has no data) as
    # (None, None) - must round-trip as a real cache HIT (a tuple),
    # not be indistinguishable from "never looked up".
    domain_info._cache_put("no-rdap-host.kh", None, None)
    assert domain_info._cache_get("no-rdap-host.kh") == (None, None)


def test_cache_get_expires_after_ttl(monkeypatch):
    domain_info._cache_put("stale-host.example", "2020-01-01", "Some Registrar")

    real_time = domain_info.time.time

    def fake_time():
        return real_time() + domain_info.CACHE_TTL_SECONDS + 1

    monkeypatch.setattr(domain_info.time, "time", fake_time)

    assert domain_info._cache_get("stale-host.example") is None


@pytest.mark.asyncio
async def test_fetch_registration_caches_a_404_and_does_not_re_query(monkeypatch):
    # A 404 (registry has no RDAP data, e.g. some ccTLDs incl. .kh) must
    # be cached so we don't re-query every scan this week - verified by
    # actually calling fetch_registration twice and confirming only one
    # real HTTP call happens.
    call_count = {"n": 0}

    class _FakeResponse:
        status_code = 404

        def json(self):
            return {}

    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url):
            call_count["n"] += 1
            return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)

    first = await domain_info.fetch_registration("no-rdap-host.kh")
    second = await domain_info.fetch_registration("no-rdap-host.kh")

    assert first == (None, None)
    assert second == (None, None)
    assert call_count["n"] == 1  # only the FIRST call should hit the network


@pytest.mark.asyncio
async def test_fetch_registration_survives_a_network_exception(monkeypatch):
    class _RaisingAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url):
            raise httpx.ConnectTimeout("simulated timeout")

    monkeypatch.setattr(httpx, "AsyncClient", _RaisingAsyncClient)

    result = await domain_info.fetch_registration("unreachable-host.example")
    assert result == (None, None)


# --- resolve_host DNS timeout -------------------------------------------

@pytest.mark.asyncio
async def test_resolve_host_returns_none_for_empty_host():
    assert await domain_info.resolve_host("") is None
    assert await domain_info.resolve_host(None) is None


@pytest.mark.asyncio
async def test_resolve_host_returns_real_ips_on_a_normal_lookup(monkeypatch):
    monkeypatch.setattr(domain_info, "_resolve_sync", lambda host: ["93.184.216.34"])
    assert await domain_info.resolve_host("example.com") == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_resolve_host_returns_none_on_a_hung_resolver(monkeypatch):
    # Regression: socket.getaddrinfo has no timeout of its own, unlike
    # every sibling outbound call in this codebase (RDAP 8s, TLS connect,
    # network trace 10s) - a slow/hanging resolver used to stall
    # resolve_host, and since analyze_url runs this inside an
    # asyncio.gather with the others, one stuck DNS lookup stalled the
    # WHOLE scan up to the system resolver's own default (20-30s).
    def hanging_resolve(host):
        time.sleep(2)  # real thread sleep - this IS what to_thread runs
        return ["203.0.113.5"]

    monkeypatch.setattr(domain_info, "_resolve_sync", hanging_resolve)
    monkeypatch.setattr(domain_info, "DNS_TIMEOUT", 0.05)

    started = time.perf_counter()
    result = await domain_info.resolve_host("slow-resolver.example")
    elapsed = time.perf_counter() - started

    assert result is None
    # Must return at (roughly) the timeout bound, not wait for the full
    # 2s sleep - proves this actually stops blocking the scan rather than
    # just silently swallowing a late result.
    assert elapsed < 1.0


@pytest.mark.asyncio
async def test_resolve_host_unresolvable_and_timed_out_are_both_none(monkeypatch):
    # A DNS timeout must degrade exactly like a genuinely unresolvable
    # host (NXDOMAIN) - both are "we don't know", and analyze_url must
    # not be able to tell them apart and score one differently.
    import socket as socket_module

    from bot.detectors.url.online import safe_net

    def raises_gaierror(host, port):
        raise socket_module.gaierror("simulated NXDOMAIN")

    # _resolve_sync now delegates to safe_net._resolve_all_sync (2026-09-16,
    # found by code review) instead of calling socket.getaddrinfo itself -
    # patch at that boundary so _resolve_sync's own try/except still runs.
    monkeypatch.setattr(safe_net, "_resolve_all_sync", raises_gaierror)
    unresolvable = await domain_info.resolve_host("nxdomain.example")
    assert unresolvable is None

    def hangs(host):
        time.sleep(2)

    monkeypatch.setattr(domain_info, "_resolve_sync", hangs)
    monkeypatch.setattr(domain_info, "DNS_TIMEOUT", 0.05)
    timed_out = await domain_info.resolve_host("slow.example")

    assert timed_out is None
    assert timed_out == unresolvable


def test_the_table_is_created_on_a_fresh_database_and_reused_idempotently(tmp_path, monkeypatch):
    # Rewritten when the per-call _connect() was replaced by a pooled,
    # per-thread connection from bot/storage/sqlite_pool.py. The property
    # is unchanged and still load-bearing: Render wipes the filesystem on
    # every deploy, so this database really does start empty in
    # production, and the DDL has to survive that.
    db_path = str(tmp_path / "idempotent.db")
    monkeypatch.setattr(domain_info, "SCAN_LOG_DB", db_path)
    sqlite_pool.close_for_thread()  # do not inherit a connection to another file

    try:
        domain_info._cache_put("example.test", "2026-01-01T00:00:00", "Registrar A")
        domain_info._cache_put("example.test", "2026-01-02T00:00:00", "Registrar B")

        assert domain_info._cache_get("example.test") == ("2026-01-02T00:00:00", "Registrar B")

        conn = sqlite3.connect(db_path)
        tables = conn.execute("select name from sqlite_master where type='table'").fetchall()
        conn.close()
        assert ("domain_info",) in tables
    finally:
        sqlite_pool.close_for_thread()
