"""
bot/detectors/url/online/domain_info.py
=========================================
Host & domain metadata — the "WHOIS & Domain Age" and "DNS
Resolution" rows of the research notes.

Two signals, both fetched asynchronously:

  1. DNS resolution (socket.getaddrinfo run in a thread): a host that
     doesn't resolve at all can't be a legitimate destination, while a
     freshly-registered domain that DOES resolve is the classic
     phishing setup.

  2. Domain creation date via RDAP (https://rdap.org). RDAP is the
     modern JSON replacement for raw whois port 43 — one HTTPS GET per
     domain, no extra package. Registration age is one of the single
     strongest phishing predictors: most malicious domains are days or
     weeks old.

Results are cached in SQLite with a 7-day TTL because registration
data never changes for an existing domain.
"""

from __future__ import annotations

import asyncio
import sqlite3
import time
from datetime import datetime, timezone

import httpx

from bot.config.config import SCAN_LOG_DB
from bot.detectors.url.online import safe_net

RDAP_TIMEOUT = 8.0
# Duplicate constant, found by code review (2026-09-16): this used to be
# its own separate `5.0` literal, coincidentally always kept equal to
# safe_net.DNS_TIMEOUT by hand rather than by anything enforcing it - both
# bound the exact same underlying call (socket.getaddrinfo, now shared via
# safe_net._resolve_all_sync, see _resolve_sync below). Aliasing to
# safe_net.DNS_TIMEOUT makes that one real value instead of two that
# happen to agree today.
DNS_TIMEOUT = safe_net.DNS_TIMEOUT
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60



def _resolve_sync(host: str) -> list[str] | None:
    # Shares safe_net._resolve_all_sync's short-lived per-host cache
    # (2026-09-16, found by code review) instead of running its own
    # independent socket.getaddrinfo - this and safe_net's own SSRF
    # resolution (network.py, cert_info.py) used to each resolve the
    # SAME host separately for the SAME scan, 3 real DNS lookups where
    # 1 would do. Resolved IPs don't depend on the `port` argument at
    # all, so a fixed placeholder port here is safe - see
    # _resolve_all_sync's own docstring on why it's keyed by host alone.
    try:
        return safe_net._resolve_all_sync(host, 0)
    except safe_net._UNRESOLVABLE_ERRORS:
        # UnicodeError (confirmed live: UnicodeEncodeError, "'idna'
        # codec can't encode... label too long") - Python's own idna
        # codec refuses to even attempt the lookup for a hostname with
        # a label over 63 characters, a real, common phishing-link
        # shape (long garbage subdomains). Only gaierror was caught
        # here originally, so this shape crashed resolve_host outright
        # instead of returning None as its own docstring promises.
        return None


async def resolve_host(host: str) -> list[str] | None:
    """IP addresses for host, [] -like None when it doesn't resolve.

    socket.getaddrinfo has no timeout parameter of its own (unlike
    cert_info.py's create_connection(timeout=...) or httpx's own
    timeout=), and a hung/slow resolver was the one outbound call in
    this codebase with no bound at all - every sibling call
    (RDAP 8s, TLS connect, network trace 10s) already has one. Since
    analyze_url runs this inside an asyncio.gather with the others, one
    stuck DNS lookup stalled the WHOLE scan, up to the system resolver's
    own default (20-30s), not just this one signal.

    asyncio.wait_for cancels the AWAIT, not the underlying OS call -
    getaddrinfo itself cannot be interrupted mid-syscall, so the
    to_thread worker keeps running in the background after this returns.
    That's an accepted, harmless leak (the thread just finishes and
    exits on its own with a result nothing reads), the same tradeoff any
    wait_for-around-a-thread has; the actual goal is only to stop it
    blocking THIS scan, not to abort the OS-level lookup.
    """
    if not host:
        return None
    try:
        return await asyncio.wait_for(asyncio.to_thread(_resolve_sync, host), timeout=DNS_TIMEOUT)
    except asyncio.TimeoutError:
        return None



def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(SCAN_LOG_DB)
    # See bot/storage/scan_log.py's init_db() for why: this file is
    # shared by several unrelated caches/logs, and WAL mode lets
    # concurrent access to different tables proceed without blocking
    # each other. Set defensively here too in case this connects first.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        create table if not exists domain_info(
            host text primary key,
            created_at text,
            registrar text,
            looked_up_at real
        )
        """
    )
    return conn


def _cache_get(host: str):
    conn = _connect()
    try:
        row = conn.execute(
            "select created_at, registrar, looked_up_at from domain_info where host = ?",
            (host,),
        ).fetchone()
    finally:
        conn.close()
    if row is None or time.time() - row[2] > CACHE_TTL_SECONDS:
        return None
    return row[0], row[1]


def _cache_put(host: str, created_at: str | None, registrar: str | None) -> None:
    conn = _connect()
    try:
        conn.execute(
            "insert or replace into domain_info(host, created_at, registrar, looked_up_at) "
            "values (?, ?, ?, ?)",
            (host, created_at, registrar, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def _parse_rdap_date(raw: str) -> str | None:
    """RDAP event dates are ISO-8601, sometimes with fractional seconds;
    normalize to a plain date string."""
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return None


async def fetch_registration(host: str) -> tuple[str | None, str | None]:
    """(creation_date_iso, registrar) for a registrable domain via RDAP.
    Returns (None, None) when RDAP has no data (some ccTLDs, incl. .kh).
    """
    cached = _cache_get(host)
    if cached is not None:
        return cached

    url = f"https://rdap.org/domain/{host}"
    try:
        async with httpx.AsyncClient(timeout=RDAP_TIMEOUT, follow_redirects=True) as client:
            response = await client.get(url)
    except Exception:                          # noqa: BLE001 - network is best-effort
        return None, None
    if response.status_code != 200:
        # 404 = registry knows nothing about it; cache the miss too so we
        # don't re-query every scan this week.
        _cache_put(host, None, None)
        return None, None

    data = response.json()
    created = registrar = None
    for event in data.get("events", []) or []:
        if event.get("eventAction") == "registration":
            created = _parse_rdap_date(event.get("eventDate") or "")
            break
    for entity in data.get("entities", []) or []:
        if "registrar" in (entity.get("roles") or []):
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        registrar = item[3]
                        break
            break

    _cache_put(host, created, registrar)
    return created, registrar


async def domain_age_days(host: str) -> int | None:
    """Days since registration, or None if unknown."""
    from bot.detectors.url.offline.lexical import registered_domain
    reg = registered_domain(host)
    created, _ = await fetch_registration(reg)
    if not created:
        return None
    try:
        created_dt = datetime.fromisoformat(created).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return max((datetime.now(timezone.utc) - created_dt).days, 0)



def score_domain_age(age_days: int | None) -> tuple[int, str] | None:
    """Turn an age into (points, reason); None adds nothing."""
    if age_days is None:
        return None
    if age_days < 30:
        return 35, f"Domain registered only {age_days} day(s) ago — brand-new domains are a classic phishing sign."
    if age_days < 90:
        return 20, f"Domain registered {age_days} days ago — still very young."
    if age_days < 365:
        return 10, f"Domain registered {age_days} days ago — less than a year old."
    return None

