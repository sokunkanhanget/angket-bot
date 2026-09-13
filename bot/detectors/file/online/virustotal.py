"""
bot/detectors/file/online/virustotal.py
==========================================
Real network call - a live VirusTotal hash lookup. Moved out of
scanner.py so the offline (filename heuristic) and online (this) halves
of file scanning are as clearly separated as url/offline vs url/online
already are.

file_vt_cache below mirrors url/online/threat_intel.py's own vt_cache:
same 7-day TTL, same "any real answer gets cached regardless of verdict"
policy. Keyed on the file's SHA-256 directly (already the right cache
key - no encoding needed, unlike a URL) - a repeat upload of the exact
same file content skips the live VT call entirely, so handlers can also
skip charging quota for a cache hit (see file_handler.py's handle_file).
"""

from __future__ import annotations

import json
import sqlite3
import time

import vt

from bot.config.config import SCAN_LOG_DB, VIRUSTOTAL_API_KEY

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
        create table if not exists file_vt_cache(
            file_hash text primary key,
            result_json text not null,
            cached_at real not null
        )
        """
    )
    return conn


def cached_result(file_hash: str) -> dict | None:
    """Fresh VT verdict for this exact SHA-256, or None. Callers use a
    non-None result both to skip the live VT call AND (handle_file) to
    skip the sender's daily file-scan quota - a repeat upload of an
    already-known file is free either way."""
    conn = _connect()
    try:
        row = conn.execute(
            "select result_json, cached_at from file_vt_cache where file_hash = ?",
            (file_hash,),
        ).fetchone()
    finally:
        conn.close()
    if row is None or time.time() - row[1] > CACHE_TTL_SECONDS:
        return None
    return json.loads(row[0])


def _cache_put(file_hash: str, result: dict) -> None:
    conn = _connect()
    try:
        conn.execute(
            "insert or replace into file_vt_cache(file_hash, result_json, cached_at) "
            "values (?, ?, ?)",
            (file_hash, json.dumps(result), time.time()),
        )
        conn.commit()
    finally:
        conn.close()


async def scan_vt_hash(file_hash: str) -> dict:
    """`checked` is the important field callers need that didn't exist
    before: `found: False` used to mean ONE thing - "VirusTotal has never
    seen this hash" - whether that was actually true (a confirmed
    NotFoundError) or VirusTotal itself was down/rate-limited/unreachable
    (any other APIError, or a raw connection failure this used to let
    propagate uncaught past this function entirely). A caller showing
    "this file's signature isn't on VirusTotal" during a real VT outage
    is actively misleading - it reads as a real (if weak) safety signal
    when there's actually no signal at all. `checked=True` means VT was
    actually reached and gave a real answer (found True or False);
    `checked=False` means it wasn't, and `found` is meaningless either way.

    Cache-first (file_vt_cache, 7-day TTL - see this module's own
    docstring): only a `checked=True` result (found True or False) is a
    real, cacheable answer - `checked=False` means VT itself couldn't be
    reached, which is never cached (same "don't cache a non-answer"
    policy threat_intel.py's URL cache uses for its own error/429 path).
    """
    cached = cached_result(file_hash)
    if cached is not None:
        return cached

    try:
        async with vt.Client(VIRUSTOTAL_API_KEY) as client:
            file_obj = await client.get_object_async(f"/files/{file_hash}")
            stats = file_obj.last_analysis_stats
            results = getattr(file_obj, "last_analysis_results", {})

            def get_engine_status(engine_name: str) -> str:
                engine_data = results.get(engine_name, {})
                category = engine_data.get("category", "undetected")
                result = engine_data.get("result")
                if category == "malicious":
                    return f"Detected ({result})"
                if category == "suspicious":
                    return f"Suspicious ({result})"
                return "Clean"

            result = {
                "checked": True,
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()),
                "top_engines": {
                    "Microsoft": get_engine_status("Microsoft"),
                    "Kaspersky": get_engine_status("Kaspersky"),
                    "BitDefender": get_engine_status("BitDefender"),
                },
            }
            _cache_put(file_hash, result)
            return result
    except vt.APIError as error:
        if error.code == "NotFoundError":
            result = {"checked": True, "found": False}
            _cache_put(file_hash, result)
            return result
        return {"checked": False, "found": False, "error": str(error)}
    except Exception as error:  # noqa: BLE001 - a connection-level failure (network down,
        # DNS, timeout - anything below the vt.APIError layer) must still
        # come back as "VT couldn't be checked", not crash the caller.
        return {"checked": False, "found": False, "error": str(error)}
