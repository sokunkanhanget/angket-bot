import sqlite3

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