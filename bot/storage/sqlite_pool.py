"""
bot/storage/sqlite_pool.py
==========================
One reused sqlite3 connection per thread, instead of a fresh
connect/close cycle on every single call.

Measured on this project's own access pattern (2000 operations against a
real WAL-mode file):

    connect + PRAGMA + query + close   1.3502 ms/op
    connect + query + close            1.3577 ms/op   (PRAGMA is free)
    reused connection + query          0.0064 ms/op
    connect + insert + commit + close  9.5716 ms/op
    reused conn + insert + commit      1.4888 ms/op

So re-running `PRAGMA journal_mode=WAL` per call costs nothing
measurable - WAL is a property of the FILE, not the connection, and
setting it again is a no-op. The real cost is the connect/close cycle
itself: ~6x on the write path, which is what the scan-logging and
page-signature calls actually do.

These calls now run inside asyncio.to_thread (see the event-loop work in
this same pass), and asyncio's default executor REUSES its worker
threads, so a thread-local connection genuinely survives from one call
to the next rather than being rebuilt each time.

Deliberately NOT a general-purpose pool:

  * ONE connection per thread, not one per (thread, path). Pointing at a
    different file closes the previous connection first. Production only
    ever uses a single SCAN_LOG_DB, so nothing churns there - but the
    test suite points SCAN_LOG_DB at a fresh tmp file per test, and
    caching every path ever seen would leak a file handle per test and
    block pytest's tmp-dir cleanup on Windows.

  * sqlite3's default check_same_thread=True is left ON. Thread-local
    storage already guarantees one connection per thread, so the safety
    net costs nothing and still catches a connection escaping its
    thread.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from contextlib import contextmanager

logger = logging.getLogger(__name__)

_local = threading.local()


def _connection_for(db_path: str) -> sqlite3.Connection:
    cached = getattr(_local, "conn", None)
    if cached is not None:
        if getattr(_local, "path", None) == db_path:
            return cached
        try:
            cached.close()
        except sqlite3.Error:                  # pragma: no cover - already unusable
            logger.debug("Discarding unusable pooled connection", exc_info=True)
        _local.conn = None
        _local.path = None

    conn = sqlite3.connect(db_path)
    # Set once per newly opened connection rather than per call. Still
    # set defensively here rather than relying on scan_log.init_db()
    # alone, because a worker thread can be the first to open a file
    # that init_db never touched - the same reason every module's own
    # _connect had this line.
    conn.execute("PRAGMA journal_mode=WAL")
    _local.conn = conn
    _local.path = db_path
    return conn


@contextmanager
def connection(db_path: str):
    """A reused, per-thread connection to `db_path`.

    Commits on a clean exit and rolls back on an exception. That rollback
    is the one thing a reused connection genuinely needs and a
    closed-per-call one never did: a write that raised half way through
    used to be discarded along with the connection, whereas now an
    open transaction would otherwise be inherited by whatever calls next
    on this same thread.
    """
    conn = _connection_for(db_path)
    try:
        yield conn
        conn.commit()
    except BaseException:
        try:
            conn.rollback()
        except sqlite3.Error:                  # pragma: no cover
            logger.debug("Rollback on pooled connection failed", exc_info=True)
        raise


def close_for_thread() -> None:
    """Drop this thread's cached connection. For tests and for any caller
    that wants to release the handle without waiting for thread exit."""
    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except sqlite3.Error:                  # pragma: no cover
            logger.debug("Closing pooled connection failed", exc_info=True)
    _local.conn = None
    _local.path = None
