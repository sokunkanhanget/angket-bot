"""
bot/url_checker/features/online/threat_intel.py
==========================================
Flow 3 of the link-checking pipeline: external threat-intelligence
feeds, starting with VirusTotal.

What VirusTotal gives us that local analysis can't:
    ~70+ antivirus / phishing blacklists (Google Safe Browsing,
    Kaspersky, ESET...) have already seen most scam links. One HTTPS
    GET answers "do known engines flag this URL?" — the single most
    authoritative signal available for KNOWN bad links.

Free Public API limits (important!):
    * 4 lookups per MINUTE
    * 500 per day
So this module is built quota-first:

    1. Every answer is cached in SQLite (vt_cache) for 7 days — a URL
       is only ever fetched once per week no matter how many times
       Telegram users send it.
    2. The caller passes live=False for URLs that look clean so far;
       we then ONLY answer from cache and never spend quota on links
       our own analysis already trusts.
    3. HTTP 429 (rate limited) is handled gracefully -> treated as
       "no data", never an error in the bot.

The module never raises; every failure degrades to None ("VT has no
opinion") because the other two flows must keep working offline.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sqlite3
import time

import httpx

from bot.config import SCAN_LOG_DB

API_BASE = "https://www.virustotal.com/api/v3"
LOOKUP_TIMEOUT = 8.0
SUBMIT_SETTLE_SECONDS = 5     # VT needs a few seconds to analyse a fresh submission
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60


# --- Scoring ----------------------------------------------------------

def score(stats: dict) -> tuple[int, str] | None:
    """Turn VT stats into (points, reason). None = VT sees nothing bad."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = stats.get("total", 0) or stats.get("engines", 0)

    if total == 0 and malicious == 0 and suspicious == 0:
        return None
    if malicious >= 5:
        return (50, f"{malicious} security engines on VirusTotal flag this "
                    f"link as malicious.")
    if malicious >= 2:
        return (40, f"{malicious} security engines on VirusTotal flag this "
                    f"link as malicious.")
    if malicious == 1:
        return (25, "1 security engine on VirusTotal flags this link as malicious.")
    if suspicious >= 1:
        return (15, f"{suspicious} engine(s) on VirusTotal consider this link suspicious.")
    return None


# --- Cache ------------------------------------------------------------

def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(SCAN_LOG_DB)
    conn.execute(
        """
        create table if not exists vt_cache(
            url_id text primary key,
            malicious integer,
            suspicious integer,
            total integer,
            looked_up_at real
        )
        """
    )
    return conn


def _cache_get(url_id: str):
    conn = _connect()
    try:
        row = conn.execute(
            "select malicious, suspicious, total, looked_up_at from vt_cache where url_id = ?",
            (url_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None or time.time() - row[3] > CACHE_TTL_SECONDS:
        return None
    return {"malicious": row[0], "suspicious": row[1], "total": row[2]}


def _cache_put(url_id: str, stats: dict) -> None:
    conn = _connect()
    try:
        conn.execute(
            "insert or replace into vt_cache(url_id, malicious, suspicious, total, looked_up_at) "
            "values (?, ?, ?, ?, ?)",
            (url_id, stats.get("malicious", 0), stats.get("suspicious", 0),
             stats.get("total", 0), time.time()),
        )
        conn.commit()
    finally:
        conn.close()


# --- Lookup -----------------------------------------------------------

def _url_identifier(url: str) -> str:
    """VirusTotal v3 identifies a URL by its unpadded base64url encoding."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def lookup(url: str, api_key: str | None, live: bool = True) -> dict | None:
    """Stats dict {malicious, suspicious, total} for a URL, or None.

    Order of operations:
      1. fresh cache hit?          -> return it (costs nothing)
      2. live allowed + API key?   -> query VT, cache, return
      3. otherwise                 -> None (no opinion)
    """
    if not api_key or not url:
        return None

    url_id = _url_identifier(url)

    cached = _cache_get(url_id)
    if cached is not None:
        # A cache row of all zeros means "VT knows nothing / was asked
        # before" — still counts as a real answer for TTL purposes but
        # scores zero points.
        return cached if (cached["malicious"] or cached["suspicious"] or cached["total"]) else None

    if not live:
        return None

    try:
        async with httpx.AsyncClient(timeout=LOOKUP_TIMEOUT) as client:
            response = await client.get(
                f"{API_BASE}/urls/{url_id}",
                headers={"x-apikey": api_key},
            )

            # 404 = VT has never seen this URL. Submit it for analysis
            # (this also spends quota, so only on the miss path), give
            # the engines a few seconds, then fetch stats once.
            if response.status_code == 404:
                sub = await client.post(
                    f"{API_BASE}/urls",
                    data={"url": url},
                    headers={"x-apikey": api_key},
                )
                if sub.status_code == 200:
                    await asyncio.sleep(SUBMIT_SETTLE_SECONDS)
                    response = await client.get(
                        f"{API_BASE}/urls/{url_id}",
                        headers={"x-apikey": api_key},
                    )
    except Exception:                          # noqa: BLE001 - network is best-effort
        return None

    if response.status_code != 200:
        # 404 = VT never saw this URL; 401 = bad key; 429 = rate limit.
        # All mean "no data right now"; do NOT cache misses so a retry
        # can happen after the rate-limit window.
        return None

    try:
        attributes = response.json()["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {}) or {}
    except (KeyError, ValueError, json.JSONDecodeError):
        return None

    result = {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total": sum(stats.get(k, 0) for k in
                     ("malicious", "suspicious", "harmless", "undetected", "timeout")),
    }

    # A freshly submitted URL often isn't analysed yet (total == 0).
    # Don't cache that, or the URL would stay "no opinion" for a week;
    # the next user who sends it will get the finished verdict instead.
    if result["total"] > 0:
        _cache_put(url_id, result)
    return result

