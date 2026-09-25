"""
tools/gate_fresh_db.py
========================
Gate checker: a completely empty SCAN_LOG_DB must still bootstrap every
cache table on first use.

Why this is the riskiest gate of the sqlite refactor: today each of the
five detector caches calls its own `_connect()`, and every one of those
runs `CREATE TABLE IF NOT EXISTS` on every single call. Routing them
through `bot/storage/sqlite_pool.py` removes that per-call setup, so if
table creation is not re-established somewhere, the caches break on any
database that does not already have the tables.

That is not a hypothetical on this deployment: Render's free tier wipes
the whole filesystem on every deploy, restart and sleep-wake, so the bot
genuinely starts from an empty SQLite file on a regular basis. A refactor
that passed every test against a warm local database would fail in
production on the next push.

Prints FRESH_DB_BOOTSTRAP_OK only after every cache has completed a real
write and a real read against a database that started empty.
"""

from __future__ import annotations

import asyncio
import inspect
import sys
import tempfile
from pathlib import Path

import _gate_env  # noqa: F401 - sys.path + utf-8 stdout bootstrap


async def _call(fn, *args):
    """Call a cache function whether it is sync (today) or async (after
    the refactor moves it onto asyncio.to_thread)."""
    result = fn(*args)
    if inspect.isawaitable(result):
        return await result
    return result


async def main() -> int:
    tmp_dir = Path(tempfile.mkdtemp(prefix="angket-gate-freshdb-"))
    fresh_db = tmp_dir / "scan_logs.db"
    assert not fresh_db.exists(), "the gate must start from a genuinely empty database"

    from bot.detectors.file.online import virustotal
    from bot.detectors.url import pipeline
    from bot.detectors.url.online import cert_info, domain_info, threat_intel

    modules = (pipeline, cert_info, domain_info, threat_intel, virustotal)

    # Every module binds SCAN_LOG_DB at import time, so repoint each one.
    # Both the module attribute and sqlite_pool's per-thread cache matter:
    # a pooled connection opened against the real database would not prove
    # anything about a fresh one.
    for module in modules:
        if not hasattr(module, "SCAN_LOG_DB"):
            print(f"FAIL: {module.__name__} has no SCAN_LOG_DB to repoint", file=sys.stderr)
            return 1
        setattr(module, "SCAN_LOG_DB", str(fresh_db))

    from bot.storage import sqlite_pool

    if hasattr(sqlite_pool, "close_for_thread"):
        sqlite_pool.close_for_thread()

    checks = [
        ("pipeline verdict cache",
         lambda: _call(pipeline._verdict_cache_put, "https://gate.example/probe", 10, ["r"], ["d"]),
         lambda: _call(pipeline._verdict_cache_get, "https://gate.example/probe")),
        ("cert_info cache",
         lambda: _call(cert_info._cache_put, "gate.example", "2026-01-01T00:00:00"),
         lambda: _call(cert_info._cache_get, "gate.example")),
        ("domain_info cache",
         lambda: _call(domain_info._cache_put, "gate.example", "2026-01-01T00:00:00", "Gate Registrar"),
         lambda: _call(domain_info._cache_get, "gate.example")),
        ("threat_intel cache",
         lambda: _call(threat_intel._cache_put, "https://gate.example/probe", {"malicious": 0}),
         lambda: _call(threat_intel._cache_get, "https://gate.example/probe")),
        ("virustotal file cache",
         lambda: _call(virustotal._cache_put, "a" * 64, {"checked": True, "found": False}),
         lambda: _call(virustotal.cached_result, "a" * 64)),
    ]

    for name, write, read in checks:
        try:
            await write()
        except Exception as error:  # noqa: BLE001 - the gate reports, it does not recover
            print(f"FAIL: {name} could not WRITE to a fresh database: "
                  f"{type(error).__name__}: {error}", file=sys.stderr)
            return 1
        try:
            value = await read()
        except Exception as error:  # noqa: BLE001
            print(f"FAIL: {name} could not READ from a fresh database: "
                  f"{type(error).__name__}: {error}", file=sys.stderr)
            return 1
        # A miss is a legitimate answer for some of these shapes, but an
        # exception is not - the table has to exist either way. Re-reading
        # is what proves the CREATE actually happened.
        del value

    if not fresh_db.exists():
        print("FAIL: no database file was ever created", file=sys.stderr)
        return 1

    print("FRESH_DB_BOOTSTRAP_OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
