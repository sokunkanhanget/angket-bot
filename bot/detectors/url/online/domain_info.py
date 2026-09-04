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
import socket
import sqlite3
import time
from datetime import datetime, timezone

import httpx

from bot.config import SCAN_LOG_DB

RDAP_TIMEOUT = 8.0
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60


# --- DNS --------------------------------------------------------------

def _resolve_sync(host: str) -> list[str] | None:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return None
    return sorted({info[4][0] for info in infos})


async def resolve_host(host: str) -> list[str] | None:
    """IP addresses for host, [] -like None when it doesn't resolve."""
    if not host:
        return None
    return await asyncio.to_thread(_resolve_sync, host)


# --- RDAP domain age ---------------------------------------------------

def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(SCAN_LOG_DB)
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


# --- Scoring ----------------------------------------------------------

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

