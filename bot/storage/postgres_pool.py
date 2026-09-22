"""
bot/storage/postgres_pool.py
==============================
Single shared Supabase Postgres connection pool (psycopg3, async).
Extracted from bot/detectors/url/offline/vectors.py (2026-09-22) so any
module needing Supabase - vectors.py's url_vectors pgvector store,
subscription.py's daily_usage/user_state - shares ONE pool instead of
each opening its own. Supabase's connection ceiling is a real,
already-hit constraint (see health_alerts.py's "Supabase pool
exhausted" alerts) - two independent pools would double that risk for
no reason.
"""

from __future__ import annotations

import logging
import time

from pgvector.psycopg import register_vector_async
from psycopg_pool import AsyncConnectionPool

from bot.config.config import SUPABASE_DB_URL

logger = logging.getLogger(__name__)

_pool: AsyncConnectionPool | None = None


async def _configure(conn) -> None:
    # register_vector_async is a no-op cost for connections that never
    # touch a vector column (subscription.py's queries never do) -
    # cheaper to register it unconditionally on the one shared pool than
    # to maintain two separate configure functions/pools.
    await register_vector_async(conn)


async def get_pool() -> AsyncConnectionPool:
    global _pool
    if _pool is None:
        # Lazy, first-message cost, NOT a startup cost - this only runs
        # once a handler first calls into Supabase, which only happens
        # on the first qualifying Telegram message the bot receives
        # after each restart, not during bot.py's main().
        start = time.perf_counter()
        _pool = AsyncConnectionPool(
            # max_size raised 5 -> 20 (2026-09-22, ahead of a pitch demo
            # expecting real concurrent user load): this ONE pool now
            # serves both vectors.py (nearly every link/text check) and
            # subscription.py (nearly every message) - 5 was already
            # thin for two independently-driven workloads sharing it,
            # and a prior "Supabase pool exhausted" incident (see
            # vectors.py's _seed_lock) showed exhaustion is a real, not
            # theoretical, failure mode. 20 is still comfortably inside
            # Supabase's free-tier (Nano compute) ceiling - confirmed
            # 60 direct / 200 Supavisor pooler connections - so this
            # process alone can't get anywhere near the real limit even
            # at 4x its old size.
            SUPABASE_DB_URL, min_size=1, max_size=20, configure=_configure,
            # Supabase's Session pooler closes idle connections server-side
            # well before this pool's own default max_idle (600s) - hit live
            # as "server closed the connection unexpectedly" when a stale
            # pooled connection got handed out unchecked. check_connection
            # verifies a connection is actually alive on checkout and
            # transparently reconnects if it isn't, instead of handing out
            # a dead one and letting the query fail.
            check=AsyncConnectionPool.check_connection,
            open=False,
        )
        await _pool.open()
        logger.info("[first-message] Supabase pool opened in %.3fs", time.perf_counter() - start)
    return _pool
