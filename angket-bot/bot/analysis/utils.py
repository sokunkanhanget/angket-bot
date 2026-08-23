import sqlite3
from datetime import datetime, timezone

from bot.config import SCAN_LOG_DB


def init_db() -> None:
    conn = sqlite3.connect(SCAN_LOG_DB)
    try:
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
        conn.commit()
    finally:
        conn.close()


def log_scan(user_id: int, item_name: str, sha256: str, malicious: int) -> None:
    conn = sqlite3.connect(SCAN_LOG_DB)
    try:
        conn.execute(
            "INSERT INTO scan_logs (user_id, item_name, sha256, malicious_count) VALUES (?, ?, ?, ?)",
            (user_id, item_name, sha256, malicious),
        )
        conn.commit()
    finally:
        conn.close()

# URL logs table
def init_url_db() -> None:
    connection = sqlite3.connect(SCAN_LOG_DB)
    try:
        connection.execute(
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
        connection.commit()
    finally:
        connection.close()

def log_url_scan(user_id: int, host: str, score: int, level: str) -> None:
    connection = sqlite3.connect(SCAN_LOG_DB)
    try:
        connection.execute(
            "insert into url_scan_logs (user_id, host, score, level, checked_at) values (?, ?, ?, ?, ?)",
            (user_id, host, score, level, datetime.now(timezone.utc).isoformat()),
        )
        connection.commit()
    finally:
        connection.close()