"""
bot/detectors/url/online/cert_info.py
=======================================
TLS certificate issuance age - freshly-issued certificates (especially
free Let's Encrypt certs, issued in seconds via ACME) are common in
fast-flux phishing: a scam domain gets registered and its cert issued
minutes before a campaign launches. Same signal family as
domain_info.py's registration-age scoring, just reading the TLS
certificate's notBefore date instead of RDAP.

httpx doesn't expose the raw peer certificate, so this uses the
stdlib `ssl` module directly - a real TLS handshake, just reading the
cert metadata off it instead of the HTTP response. Validated against
next-gen-test/concepts/cert-age-py before landing here.

Cached in SQLite with a 7-day TTL, same pattern/DB as domain_info.py -
a cert's issuance date never changes once observed.
"""

from __future__ import annotations

import asyncio
import socket
import sqlite3
import ssl
import time
from datetime import datetime, timezone

from bot.config import SCAN_LOG_DB

TIMEOUT = 8.0
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(SCAN_LOG_DB)
    # See bot/storage/scan_log.py's init_db() for why: this file is
    # shared by several unrelated caches/logs, and WAL mode lets
    # concurrent access to different tables proceed without blocking
    # each other. Set defensively here too in case this connects first.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        create table if not exists cert_info(
            host text primary key,
            issued_at text,
            looked_up_at real
        )
        """
    )
    return conn


def _cache_get(host: str) -> tuple[bool, str | None]:
    """(was_cached, issued_at). Returning just `issued_at` used to
    conflate "never looked up / expired" with "looked up, found no
    cert data" - both are None, so a cached negative result (no cert,
    handshake failed, etc.) was indistinguishable from no cache entry
    at all, silently defeating the cache for exactly the miss case and
    triggering a real TLS handshake retry on every subsequent scan of
    that host. `was_cached` makes the two cases distinguishable."""
    conn = _connect()
    try:
        row = conn.execute(
            "select issued_at, looked_up_at from cert_info where host = ?", (host,)
        ).fetchone()
    finally:
        conn.close()
    if row is None or time.time() - row[1] > CACHE_TTL_SECONDS:
        return False, None
    return True, row[0]


def _cache_put(host: str, issued_at: str | None) -> None:
    conn = _connect()
    try:
        conn.execute(
            "insert or replace into cert_info(host, issued_at, looked_up_at) values (?, ?, ?)",
            (host, issued_at, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def _get_cert_sync(host: str, port: int = 443) -> dict | None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert()
    except Exception:                          # noqa: BLE001 - no cert, timeout, refused, self-signed...
        return None


def _parse_cert_date(raw: str) -> str | None:
    """ssl module gives dates like 'Jan  1 00:00:00 2024 GMT'."""
    try:
        return datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return None


async def cert_issued_days_ago(host: str, port: int = 443) -> int | None:
    """Days since the TLS cert's notBefore date, or None if unknown
    (no cert, connection failed, plain HTTP, etc.)."""
    if not host:
        return None

    was_cached, cached = _cache_get(host)
    if not was_cached:
        cert = await asyncio.to_thread(_get_cert_sync, host, port)
        issued = None
        if cert and "notBefore" in cert:
            issued = _parse_cert_date(cert["notBefore"])
        _cache_put(host, issued)
        cached = issued

    if not cached:
        return None
    try:
        issued_dt = datetime.fromisoformat(cached)
    except ValueError:
        return None
    return max((datetime.now(timezone.utc) - issued_dt).days, 0)


def score_cert_age(age_days: int | None) -> tuple[int, str] | None:
    """Same shape as domain_info.py::score_domain_age, deliberately
    scored lower at each tier: CDNs/load balancers rotate certs
    routinely (confirmed live during prototyping - wikipedia.org's
    real cert was only 24 days old from ordinary Let's Encrypt
    auto-renewal), so cert freshness alone is a weaker signal than
    domain-registration freshness."""
    if age_days is None:
        return None
    if age_days < 7:
        return 20, f"TLS certificate issued only {age_days} day(s) ago — very fresh for a real business."
    if age_days < 30:
        return 10, f"TLS certificate issued {age_days} days ago — still quite new."
    return None
