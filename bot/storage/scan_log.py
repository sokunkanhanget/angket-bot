from datetime import datetime, timezone

from bot.config.config import SCAN_LOG_DB
from bot.storage.sqlite_pool import connection


def init_db() -> None:
    with connection(SCAN_LOG_DB) as conn:
        # WAL mode is a property of the DATABASE FILE, not this
        # connection - setting it once applies for every future
        # connection from every module sharing this same file
        # (scan_log.py/vectors.py's MinHash tables/domain_info.py/
        # cert_info.py/threat_intel.py/pipeline.py's verdict cache).
        # Under the default rollback-journal mode, a write to ANY ONE
        # of those unrelated tables locks the WHOLE FILE, blocking
        # reads/writes to all the others - WAL lets them proceed
        # concurrently instead. sqlite_pool.connection() now sets it on
        # each newly opened connection, so it is also covered for a
        # worker thread that opens the file before this ever runs.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                item_name TEXT,
                sha256 TEXT,
                malicious_count INTEGER
            )
            """
        )


def log_scan(user_id: int, item_name: str, sha256: str, malicious: int) -> None:
    with connection(SCAN_LOG_DB) as conn:
        conn.execute(
            "INSERT INTO scan_logs (user_id, item_name, sha256, malicious_count) VALUES (?, ?, ?, ?)",
            (user_id, item_name, sha256, malicious),
        )


def init_url_db() -> None:
    with connection(SCAN_LOG_DB) as conn:
        conn.execute(
            """
            create table if not exists url_scan_logs(
                id integer primary key autoincrement,
                user_id integer,
                host text,
                score integer,
                level text,
                checked_at text
            )
            """
        )


def log_url_scan(user_id: int, host: str, score: int, level: str) -> None:
    with connection(SCAN_LOG_DB) as conn:
        conn.execute(
            "insert into url_scan_logs (user_id, host, score, level, checked_at) values (?, ?, ?, ?, ?)",
            (user_id, host, score, level, datetime.now(timezone.utc).isoformat()),
        )
