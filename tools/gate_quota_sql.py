"""
tools/gate_quota_sql.py
=========================
Gate checker: the REAL quota-reservation SQL in bot/storage/subscription.py
must be atomic and correct against real Postgres.

The test suite replaces every subscription function with an in-memory fake,
so the actual statements never run there - and a broken statement would
fail silently, because every quota gate fails OPEN on a database error.

Runs the exact _RESERVE_SQL / _REFUND_SQL strings inside ONE transaction
that is always rolled back, for sentinel user_id -1 (Telegram ids are
positive, so it can never be a real user). Nothing is persisted.

Checks, with a limit of 3:
  - three reservations succeed (counter 1, 2, 3), the fourth is refused
  - a refund frees exactly one slot, which can then be taken again
  - a refund never drives the counter below zero
"""

from __future__ import annotations

import asyncio
import sys
from datetime import date

import _gate_env  # noqa: F401 - sys.path + utf-8 stdout bootstrap

SENTINEL_USER = -1
LIMIT = 3


async def main() -> int:
    import psycopg

    from bot.config.config import SUPABASE_DB_URL
    from bot.storage import subscription as sub

    reserve = sub._RESERVE_SQL.format(column="links_messages_used")
    refund = sub._REFUND_SQL.format(column="links_messages_used")
    today = date.today()

    async with await psycopg.AsyncConnection.connect(SUPABASE_DB_URL, connect_timeout=10) as conn:
        try:
            results = []
            for _ in range(LIMIT + 1):
                cur = await conn.execute(reserve, (SENTINEL_USER, today, LIMIT))
                row = await cur.fetchone()
                results.append(row[0] if row else None)
            if results != [1, 2, 3, None]:
                print(f"FAIL: reservations returned {results}, expected [1, 2, 3, None]", file=sys.stderr)
                return 1

            await conn.execute(refund, (SENTINEL_USER, today))
            cur = await conn.execute(reserve, (SENTINEL_USER, today, LIMIT))
            if (await cur.fetchone()) is None:
                print("FAIL: a refunded slot could not be taken again", file=sys.stderr)
                return 1

            for _ in range(LIMIT + 2):
                await conn.execute(refund, (SENTINEL_USER, today))
            cur = await conn.execute(
                "select links_messages_used from daily_usage where user_id = %s and usage_date = %s",
                (SENTINEL_USER, today),
            )
            remaining = (await cur.fetchone())[0]
            if remaining != 0:
                print(f"FAIL: over-refunding left the counter at {remaining}, expected 0", file=sys.stderr)
                return 1
        finally:
            await conn.rollback()

        cur = await conn.execute("select count(*) from daily_usage where user_id = %s", (SENTINEL_USER,))
        if (await cur.fetchone())[0] != 0:
            print("FAIL: sentinel rows survived the rollback", file=sys.stderr)
            return 1
        await conn.rollback()

    print("QUOTA_SQL_ATOMIC_OK")
    return 0


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    sys.exit(asyncio.run(main()))
