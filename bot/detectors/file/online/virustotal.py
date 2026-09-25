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

import asyncio
import json
import time

from bot.config.config import SCAN_LOG_DB, VIRUSTOTAL_API_KEY, VIRUSTOTAL_API_KEY_BACKUP
from bot.storage import sqlite_pool

# `vt` is imported lazily (2026-09-24, performance review). It pulls in
# aiohttp, together a measured ~0.18s+ of the bot's cold-start import
# phase on this machine and proportionally more on Render's slower free
# tier - paid on every single restart even though this module is only
# ever reached when a user actually uploads a FILE. Python caches
# modules in sys.modules, so the deferred import costs nothing after the
# first real file scan.
#
# Exposed through a module-level __getattr__ (PEP 562) rather than only
# importing inside each function, because `vt` must still resolve as an
# ATTRIBUTE of this module: the tests patch
# "bot.detectors.file.online.virustotal.vt.Client", which has to be able
# to traverse virustotal.vt. This keeps that working untouched while
# still never importing vt at startup. It resolves to the exact same
# global vt module the functions below import, so patching it has
# exactly the same effect it always did.


def __getattr__(name: str):
    if name == "vt":
        import vt

        return vt
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

CACHE_TTL_SECONDS = 7 * 24 * 60 * 60


def _ensure_table(conn) -> None:
    """Kept rather than moved to a one-time startup init - see
    cert_info._ensure_table for the reasoning. What was removed is the
    per-call connect plus `PRAGMA journal_mode=WAL` (a real disk write),
    which sqlite_pool now does once per thread instead of once per
    cache lookup."""
    conn.execute(
        """
        create table if not exists file_vt_cache(
            file_hash text primary key,
            result_json text not null,
            cached_at real not null
        )
        """
    )


def cached_result(file_hash: str) -> dict | None:
    """Fresh VT verdict for this exact SHA-256, or None. Callers use a
    non-None result both to skip the live VT call AND (handle_file) to
    skip the sender's daily file-scan quota - a repeat upload of an
    already-known file is free either way.

    Stays synchronous: async callers hand it to asyncio.to_thread, and
    the one synchronous caller (scan_vt_hash's own early return) already
    runs inside a thread."""
    with sqlite_pool.connection(SCAN_LOG_DB) as conn:
        _ensure_table(conn)
        row = conn.execute(
            "select result_json, cached_at from file_vt_cache where file_hash = ?",
            (file_hash,),
        ).fetchone()
    if row is None or time.time() - row[1] > CACHE_TTL_SECONDS:
        return None
    return json.loads(row[0])


def _cache_put(file_hash: str, result: dict) -> None:
    with sqlite_pool.connection(SCAN_LOG_DB) as conn:
        _ensure_table(conn)
        conn.execute(
            "insert or replace into file_vt_cache(file_hash, result_json, cached_at) "
            "values (?, ?, ?)",
            (file_hash, json.dumps(result), time.time()),
        )


FETCH_TIMEOUT_SECONDS = 15  # vt.Client's own default is 300s (unbounded in
# practice) - every other outbound call in this codebase is explicitly
# bounded (network 10s, RDAP/TLS 8s, Gemini 25s); this was the one real
# gap (found via security/networking review, 2026-09-22). Without this,
# a single hung VT connection could block one file scan for up to 5
# minutes, or ~10 with the backup-key retry below - unacceptable under
# real concurrent load.


async def _fetch_from_vt(file_hash: str, api_key: str) -> dict:
    """One real lookup attempt against a specific key. Returns the
    "malicious found" shape on success; raises vt.APIError (NotFoundError
    included) or a raw connection exception straight through - scan_vt_hash
    decides what each of those means (a real "not found" answer, a
    quota error worth retrying on the backup key, or any other failure)."""
    import vt

    async with vt.Client(api_key, timeout=FETCH_TIMEOUT_SECONDS) as client:
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

        return {
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

    VIRUSTOTAL_API_KEY_BACKUP (2026-09-21): a one-shot retry against a
    second key, but ONLY on a quota-exhaustion error specifically - any
    other APIError (a real NotFoundError, or some other real API
    problem) means retrying with a different key wouldn't change the
    outcome, so it isn't attempted. Mirrors gemini_retry.py's own
    "retry once, quota-errors only" shape for the primary/backup key
    pattern, adapted to the vt SDK's exception shape instead of a raw
    HTTP status code.
    """
    cached = await asyncio.to_thread(cached_result, file_hash)
    if cached is not None:
        return cached

    import vt

    last_error: Exception | None = None
    for api_key in filter(None, (VIRUSTOTAL_API_KEY, VIRUSTOTAL_API_KEY_BACKUP)):
        try:
            result = await _fetch_from_vt(file_hash, api_key)
            await asyncio.to_thread(_cache_put, file_hash, result)
            return result
        except vt.APIError as error:
            if error.code == "NotFoundError":
                result = {"checked": True, "found": False}
                await asyncio.to_thread(_cache_put, file_hash, result)
                return result
            last_error = error
            if error.code != "QuotaExceededError":
                break  # not a quota error - a different key won't help, don't waste the retry
        except Exception as error:  # noqa: BLE001 - a connection-level failure (network down,
            # DNS, timeout - anything below the vt.APIError layer) must still
            # come back as "VT couldn't be checked", not crash the caller.
            # Not quota-shaped either, so don't retry with the backup key.
            last_error = error
            break

    return {"checked": False, "found": False, "error": str(last_error)}
