"""
tests/test_sqlite_pool.py
=========================
The per-thread reused sqlite3 connection behind scan_log.py and
vectors.py's MinHash page tables.

Every SQLite call in this project used to open and close its own
connection. Measured over 2000 operations on a real WAL file: a
connect + insert + commit + close cycle costs 9.5716ms against 1.4888ms
on a reused connection, and a read 1.3577ms against 0.0064ms.
"""

import sqlite3
import threading

import pytest

from bot.storage import sqlite_pool


@pytest.fixture(autouse=True)
def clean_pool():
    sqlite_pool.close_for_thread()
    yield
    sqlite_pool.close_for_thread()


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "pool.db")


def test_the_same_connection_is_reused_for_the_same_path(db):
    with sqlite_pool.connection(db) as first:
        pass
    with sqlite_pool.connection(db) as second:
        pass

    assert first is second


def test_wal_is_active_on_the_file(db):
    with sqlite_pool.connection(db) as conn:
        conn.execute("create table t(a)")

    # Read it back on a completely independent connection - WAL is a
    # property of the FILE, so it has to be visible from outside the pool.
    independent = sqlite3.connect(db)
    try:
        mode = independent.execute("pragma journal_mode").fetchone()[0]
    finally:
        independent.close()

    assert mode.lower() == "wal"


def test_pointing_at_a_new_path_closes_the_previous_connection(tmp_path):
    # One connection per THREAD, not one per path ever seen. The test
    # suite repoints SCAN_LOG_DB at a fresh tmp file per test, so caching
    # every path would leak a handle per test and block pytest's tmp
    # cleanup on Windows.
    first_path = str(tmp_path / "one.db")
    second_path = str(tmp_path / "two.db")

    with sqlite_pool.connection(first_path) as first:
        first.execute("create table t(a)")
    with sqlite_pool.connection(second_path) as second:
        second.execute("create table t(a)")

    assert first is not second
    with pytest.raises(sqlite3.ProgrammingError):
        first.execute("select 1")


def test_each_thread_gets_its_own_connection(db):
    with sqlite_pool.connection(db) as conn:
        conn.execute("create table t(a)")
    main_thread_conn = conn

    from_worker = {}

    def in_worker():
        try:
            with sqlite_pool.connection(db) as worker_conn:
                worker_conn.execute("insert into t values (1)")
            from_worker["conn"] = worker_conn
        finally:
            sqlite_pool.close_for_thread()

    thread = threading.Thread(target=in_worker)
    thread.start()
    thread.join()

    # sqlite3's check_same_thread stays ON, so a shared connection would
    # have raised rather than silently worked.
    assert from_worker["conn"] is not main_thread_conn
    with sqlite_pool.connection(db) as conn:
        assert conn.execute("select count(*) from t").fetchone()[0] == 1


def test_a_clean_exit_commits(db):
    with sqlite_pool.connection(db) as conn:
        conn.execute("create table t(a)")
        conn.execute("insert into t values (7)")

    independent = sqlite3.connect(db)
    try:
        assert independent.execute("select a from t").fetchall() == [(7,)]
    finally:
        independent.close()


def test_an_exception_rolls_back_and_leaves_no_open_transaction(db):
    # The one thing a reused connection genuinely needs that a
    # closed-per-call one never did. A write that raised used to be
    # discarded along with the connection; without the rollback an open
    # transaction would now be inherited by the next caller on this
    # thread.
    with sqlite_pool.connection(db) as conn:
        conn.execute("create table t(a)")

    with pytest.raises(RuntimeError):
        with sqlite_pool.connection(db) as conn:
            conn.execute("insert into t values (1)")
            raise RuntimeError("boom")

    assert not conn.in_transaction

    with sqlite_pool.connection(db) as conn:
        assert conn.execute("select count(*) from t").fetchone()[0] == 0

    independent = sqlite3.connect(db)
    try:
        assert independent.execute("select count(*) from t").fetchone()[0] == 0
    finally:
        independent.close()


def test_close_for_thread_lets_the_next_call_rebuild(db):
    with sqlite_pool.connection(db) as first:
        first.execute("create table t(a)")

    sqlite_pool.close_for_thread()

    with sqlite_pool.connection(db) as second:
        second.execute("insert into t values (1)")

    assert second is not first
