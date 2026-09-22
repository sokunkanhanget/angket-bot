"""
bot/detectors/url/offline/vectors.py
======================================
Vector search over links, page text, and scam-message patterns.

The url_vectors similarity store (kind='brand'|'phish'|'seen'|'scam_pattern')
is backed by Supabase Postgres + pgvector - migrated from SQLite (see
next-gen-test/concepts/vector-search-py/vector-search-postgres.py for the
earlier prototype, and the session notes for why: SQLite's brute-force
"fetch every row, unpack every BLOB, compute cosine in Python" scan had
no real index, and the MSVC build blocker that stalled the local-Postgres
prototype doesn't apply to Supabase's hosted, precompiled pgvector).
MinHash-LSH page dedup (below) is a SEPARATE mechanism and stays on
SQLite - it was never in scope for this migration.

  * `embed()` turns any string (URL syntax, page title/text, message
    text) into a fixed-length SPARSE numeric vector using feature
    hashing of word tokens + character n-grams. No ML model needed,
    works offline, and captures enough signal that
    "ababank-secure-login.tk" lands close to known phishing patterns
    while "ababank.com" sits next to the official brand vectors. This
    return type and its callers (embed/cosine tests, MinHash) are
    UNCHANGED by the Postgres migration - only the STORAGE layer moved.

  * Vectors are L2-normalized so COSINE SIMILARITY is a plain dot
    product - `<=>` (pgvector's cosine distance operator) returns
    `1 - cosine_similarity`, so `nearest()` converts back with `1 - d`.

  * `nearest()` is now a real indexed ANN search (HNSW index on
    `embedding vector_cosine_ops`), not a brute-force Python loop -
    scales far past the "tens of thousands of rows" ceiling the old
    SQLite approach was explicitly limited to.

Every public function that touches url_vectors is now async
(upsert_vector, nearest, seed) - callers must await them. Everything
below the "MinHash-LSH" heading is unchanged, sync, SQLite-backed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import struct
import time

logger = logging.getLogger(__name__)

from bot.config.config import SCAN_LOG_DB
from bot.storage import sqlite_pool
from bot.storage.postgres_pool import get_pool as _get_pool

DIM = 256          # vector dimensionality
NGRAM = 4          # character n-gram size
# [a-z0-9]+ alone left this completely blind to Khmer-only text - a
# pure-Khmer message tokenized to nothing, so embed() returned {} and
# both nearest_scam_pattern() and nearest() silently found no match at
# all (not "low similarity" - literally no signal), for a Khmer-first
# bot. The Khmer block (U+1780-U+17FF) and Khmer Symbols (U+19E0-U+19FF)
# are matched as pseudo-tokens the same way an ASCII word is - no real
# word-boundary segmentation exists for Khmer script, but this still
# feeds the same char-n-gram machinery real content to work with.
# Verified live: embed() on a pure-Khmer scam-style message went from a
# 0-dim vector to 37 dims with this change.
_TOKEN_RE = re.compile(r"[a-z0-9]+|[ក-៿᧠-᧿]+")

LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _hash_token(token: str):
    """Signed hashing: one positive/negative bucket index per token."""
    digest = hashlib.md5(token.encode("utf-8")).digest()
    idx = int.from_bytes(digest[:4], "little") % DIM
    sign = 1 if digest[4] % 2 == 0 else -1
    return idx, sign


def embed(text: str) -> dict[int, float]:
    """Sparse hashed embedding: word tokens + char n-grams, de-leeted."""
    text = (text or "").lower().translate(LEET_MAP)
    vec: dict[int, float] = {}

    def _add(token: str, weight: float = 1.0):
        idx, sign = _hash_token(token)
        vec[idx] = vec.get(idx, 0.0) + sign * weight

    for token in _TOKEN_RE.findall(text):
        if len(token) >= 2:
            _add("w:" + token, 1.0)
        padded = f"^{token}$"
        for i in range(len(padded) - NGRAM + 1):
            _add("c:" + padded[i:i + NGRAM], 0.5)

    norm = sum(v * v for v in vec.values()) ** 0.5
    if norm == 0:
        return {}
    return {i: v / norm for i, v in vec.items()}


def cosine(a: dict[int, float], b: dict[int, float]) -> float:
    """Both vectors are L2-normalized, so cosine = dot product."""
    if not a or not b:
        return 0.0
    if len(b) < len(a):
        a, b = b, a
    return sum(v * b.get(i, 0.0) for i, v in a.items())


def _densify(vec: dict[int, float]) -> list[float]:
    """Sparse {index: value} -> dense DIM-length list, for pgvector -
    embed()'s sparse return type stays the public contract (tests and
    other callers rely on it); this is purely a storage-boundary detail,
    the same role _pack()/_unpack() played for SQLite's BLOB column."""
    dense = [0.0] * DIM
    for i, v in vec.items():
        dense[i] = v
    return dense


# --- Postgres-backed k-NN (Supabase + pgvector) -------------------------
# Pool itself now lives in bot/storage/postgres_pool.py (2026-09-22) -
# shared with subscription.py's daily_usage/user_state tables instead of
# each module opening its own pool against Supabase's limited connection
# ceiling. _get_pool alias kept so every call site below (upsert_vector,
# nearest, seed, etc.) is untouched.


async def upsert_vector(kind: str, key: str, text: str, label: str | None = None) -> None:
    """Store/refresh the embedding of one URL, brand profile, or scam
    pattern. One-at-a-time, live-scan storage (a URL just checked, a
    correction just made) - for bulk reference-data loading see
    upsert_vectors_batch(), which seed() uses instead."""
    vec = _densify(embed(text))
    pool = await _get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            """
            insert into url_vectors (kind, key, label, embedding)
            values (%s, %s, %s, %s::vector)
            on conflict (kind, key) do update
            set label = excluded.label, embedding = excluded.embedding, added_at = now()
            """,
            (kind, key.lower(), label, vec),
        )


async def upsert_vectors_batch(rows: list[tuple[str, str, str, str | None]]) -> None:
    """Bulk version of upsert_vector: embeds and writes many (kind, key,
    text, label) rows in ONE round trip instead of one per row.

    seed()'s reference-data load used to fire 144+ individual
    upsert_vector() calls concurrently via asyncio.gather - but the pool
    caps out at 5 connections, so those queued into ~29 serialized
    batches. Measured live: ~28 seconds on a cold restart. Embedding
    computation is pure local CPU (no network), so there's no reason it
    can't all happen before a single INSERT - only the actual database
    write needs the round trip, and Postgres has no trouble with a
    multi-row VALUES list (144 rows x 4 params is nowhere near its
    65535-parameter limit).
    """
    if not rows:
        return
    values_sql = []
    params: list = []
    for kind, key, text, label in rows:
        vec = _densify(embed(text))
        values_sql.append("(%s, %s, %s, %s::vector)")
        params.extend([kind, key.lower(), label, vec])
    pool = await _get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            f"""
            insert into url_vectors (kind, key, label, embedding)
            values {", ".join(values_sql)}
            on conflict (kind, key) do update
            set label = excluded.label, embedding = excluded.embedding, added_at = now()
            """,
            params,
        )


async def nearest(text: str, k: int = 3, kinds: tuple[str, ...] | None = None):
    """k most similar stored vectors to `text` -> [(similarity, kind, key, label)].

    Uses the HNSW index (embedding vector_cosine_ops) - real ANN search,
    not a Python-side brute-force scan. `<=>` is pgvector's cosine
    DISTANCE operator (1 - cosine_similarity), so results are converted
    back to similarity before returning, matching the old SQLite-backed
    function's contract exactly.
    """
    q = embed(text)
    if not q:
        return []
    query_vec = _densify(q)
    pool = await _get_pool()
    async with pool.connection() as conn:
        if kinds:
            cur = await conn.execute(
                """
                select kind, key, label, 1 - (embedding <=> %s::vector) as similarity
                from url_vectors
                where kind = any(%s)
                order by embedding <=> %s::vector
                limit %s
                """,
                (query_vec, list(kinds), query_vec, k),
            )
        else:
            cur = await conn.execute(
                """
                select kind, key, label, 1 - (embedding <=> %s::vector) as similarity
                from url_vectors
                order by embedding <=> %s::vector
                limit %s
                """,
                (query_vec, query_vec, k),
            )
        rows = await cur.fetchall()
    return [(float(similarity), kind, key, label) for kind, key, label, similarity in rows]


# --- MinHash-LSH for near-duplicate pages (SQLite) ---------------------
#
# Connections come from bot/storage/sqlite_pool.py: one reused connection
# per thread instead of a connect/close cycle per call. These functions
# run under asyncio.to_thread, and asyncio's default executor reuses its
# worker threads, so the connection genuinely survives between calls.
# Measured: a connect + insert + commit + close cycle costs 9.57ms
# against 1.49ms on a reused connection. WAL mode is still set on each
# newly opened connection, inside the pool.

NUM_PERM = 64


def minhash_signature(text: str) -> bytes:
    """64-permutation MinHash signature of shingles, packed as BLOB."""
    text = re.sub(r"\s+", " ", (text or "").lower())
    shingles = {text[i:i + 8] for i in range(0, max(len(text) - 7, 1))}
    if not shingles:
        return b"\x00" * (NUM_PERM * 4)
    sig = []
    for p in range(NUM_PERM):
        minimum = min(
            int.from_bytes(hashlib.md5((str(p) + s).encode()).digest()[:4], "little")
            for s in shingles
        )
        sig.append(minimum)
    return struct.pack(f"<{NUM_PERM}I", *sig)


def minhash_similarity(sig_a: bytes, sig_b: bytes) -> float:
    if not sig_a or len(sig_a) != len(sig_b):
        return 0.0
    matches = sum(1 for a, b in zip(struct.unpack(f"<{NUM_PERM}I", sig_a),
                                    struct.unpack(f"<{NUM_PERM}I", sig_b)) if a == b)
    return matches / NUM_PERM


# --- LSH banding: an EXACT prefilter, not an approximate one -----------
#
# nearest_page() used to load EVERY row of page_minhash and compute
# similarity in Python one row at a time. Measured on real signatures:
# 11ms at 1k rows, 52ms at 10k, 256ms at 50k - linear, on the hot path of
# every scan that fetches a page, and the table only ever grows.
#
# Textbook LSH banding fixes the cost but is PROBABILISTIC - it misses a
# true near-duplicate some fraction of the time, which would mean
# silently losing real detections. This banding is instead exact, by
# counting rather than probability:
#
#   A pair at similarity >= NEARDUP_THRESHOLD (0.90, see pipeline.py)
#   matches on at least ceil(0.90 * 64) = 58 of NUM_PERM=64 positions,
#   so it MISMATCHES on at most 64 - 58 = 6.
#
#   Split the signature into 6 + 1 = 7 bands. Six mismatched positions
#   can fall in at most six distinct bands, so at least one band is
#   guaranteed byte-identical for every pair above the threshold.
#
# So indexing the bands and only comparing candidates that share a whole
# band cannot miss anything the full scan would have found: zero false
# negatives, guaranteed by pigeonhole. False POSITIVE candidates are
# still filtered by the exact minhash_similarity() check afterwards, so
# the returned value is bit-for-bit what the full scan returned.
#
# INVARIANT: NUM_BANDS must stay >= (NUM_PERM - ceil(threshold*NUM_PERM)) + 1.
# Lowering NEARDUP_THRESHOLD without raising NUM_BANDS would break
# exactness - locked in by test_lsh_band_count_is_exact_for_threshold.
NUM_BANDS = 7


def _band_bounds() -> list[tuple[int, int]]:
    """Start/end offsets partitioning all NUM_PERM positions into
    NUM_BANDS contiguous bands. Sizes differ by at most one when the
    split isn't even (64 into 7 gives 10,9,9,9,9,9,9); the pigeonhole
    argument above only needs a partition, not equal sizes."""
    bounds = []
    start = 0
    for b in range(NUM_BANDS):
        size = NUM_PERM // NUM_BANDS + (1 if b < NUM_PERM % NUM_BANDS else 0)
        bounds.append((start, start + size))
        start += size
    return bounds


def _band_keys(sig: bytes) -> list[str]:
    """One lookup key per band: "<band index>:<hash of that band's bytes>".
    Hashed rather than stored raw so the key is a short fixed-width
    string regardless of band size."""
    keys = []
    for index, (start, end) in enumerate(_band_bounds()):
        chunk = sig[start * 4:end * 4]
        keys.append(f"{index}:{hashlib.md5(chunk).hexdigest()[:16]}")
    return keys


def _ensure_page_tables(conn) -> None:
    conn.execute(
        """
        create table if not exists page_minhash(
            host text primary key,
            sig blob not null,
            checked_at text
        )
        """
    )
    conn.execute(
        """
        create table if not exists page_minhash_bands(
            band_key text not null,
            host text not null,
            primary key (band_key, host)
        )
        """
    )
    conn.execute(
        "create index if not exists idx_page_minhash_bands_key on page_minhash_bands(band_key)"
    )


def _backfill_bands(conn) -> None:
    """One-time population of the band index from rows written before it
    existed. Without this, every pre-existing page signature would be
    invisible to the banded lookup - a silent loss of exactly the
    historical data the near-duplicate check exists to compare against."""
    if conn.execute("select 1 from page_minhash_bands limit 1").fetchone():
        return
    rows = conn.execute("select host, sig from page_minhash").fetchall()
    if not rows:
        return
    conn.executemany(
        "insert or ignore into page_minhash_bands(band_key, host) values (?, ?)",
        [(key, host) for host, sig in rows for key in _band_keys(sig)],
    )


def store_page_signature(host: str, page_text: str) -> bytes:
    """Save a page's MinHash under its host; returns the signature."""
    sig = minhash_signature(page_text)
    host = host.lower()
    with sqlite_pool.connection(SCAN_LOG_DB) as conn:
        _ensure_page_tables(conn)
        _backfill_bands(conn)
        conn.execute(
            "insert or replace into page_minhash(host, sig, checked_at) values (?, ?, ?)",
            (host, sig, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        )
        # This host's OLD band rows have to go: a re-scan whose content
        # changed would otherwise stay indexed under the bands of the
        # page it used to serve.
        conn.execute("delete from page_minhash_bands where host = ?", (host,))
        conn.executemany(
            "insert or ignore into page_minhash_bands(band_key, host) values (?, ?)",
            [(key, host) for key in _band_keys(sig)],
        )
    return sig


def nearest_page(host: str, sig: bytes) -> tuple[str, float] | None:
    """Closest stored page signature to `sig`, excluding `host` itself.

    Compares only against hosts sharing at least one whole MinHash band,
    which provably cannot exclude anything at or above
    NEARDUP_THRESHOLD (see the NUM_BANDS comment). Returns the same
    (host, similarity) shape the full scan did.
    """
    host = host.lower()
    keys = _band_keys(sig)
    placeholders = ", ".join("?" * len(keys))
    with sqlite_pool.connection(SCAN_LOG_DB) as conn:
        _ensure_page_tables(conn)
        _backfill_bands(conn)
        rows = conn.execute(
            f"""
            select m.host, m.sig
            from page_minhash m
            where m.host != ?
              and m.host in (
                  select host from page_minhash_bands where band_key in ({placeholders})
              )
            """,
            (host, *keys),
        ).fetchall()
    best_host, best_sim = None, 0.0
    for other_host, other_sig in rows:
        sim = minhash_similarity(sig, other_sig)
        if sim > best_sim:
            best_host, best_sim = other_host, sim
    return (best_host, best_sim) if best_host else None


# --- Seed data --------------------------------------------------------

PHISH_PATTERNS = [
    "{brand}-secure-login.verify-account.tk",
    "{brand}.support-team.cf",
    "login.{brand}.verify-user.ml",
    "{brand}-wallet-connect.ga",
    "{brand}.account-suspended.gq",
    "secure{brand}.com",
    "{brand}-update-billing.info",
]


def _brand_and_phish_rows() -> list[tuple[str, str, str, str | None]]:
    """The (kind, key, text, label) rows seed() writes for brand/phishing-
    pattern reference data. Split out as a pure function (no DB access)
    so the exact row set can be unit-tested and hashed for the
    fingerprint check below without needing a real connection - and so
    tests/conftest.py's fake vector store can build its own seed data
    from this SAME source instead of a hand-duplicated copy."""
    from bot.detectors.url.offline.lexical import PROTECTED_BRANDS

    brand_rows = [
        ("brand", domain, domain, label)
        for domain, label in PROTECTED_BRANDS.items()
    ]
    # Keyed and deduped by brand_name (domain.split(".")[0]), not by
    # domain: a real brand that legitimately operates more than one
    # domain (telegram.org/telegram.me/t.me - see PROTECTED_BRANDS)
    # shares the same brand_name root across those entries, so without
    # this dedup, telegram.me would generate BYTE-IDENTICAL synthetic
    # phishing-pattern rows to telegram.org's (same key, same text) -
    # wasted, colliding seed data, not extra detection coverage. Caught
    # live by test_fake_vector_store_seed_matches_real_row_count when
    # telegram.me/t.me were added.
    seen_brand_names: set[str] = set()
    phish_rows = []
    for domain, label in PROTECTED_BRANDS.items():
        brand_name = domain.split(".")[0]
        if brand_name in seen_brand_names:
            continue
        seen_brand_names.add(brand_name)
        for pattern in PHISH_PATTERNS:
            phish_rows.append((
                "phish", pattern.format(brand=brand_name),
                pattern.format(brand=brand_name), f"{label} impersonation pattern",
            ))
    return brand_rows + phish_rows


# A sentinel row (never a real brand/phish/seen/scam_pattern kind, so it
# can never be picked up by nearest()'s kind-filtered queries - see
# pipeline.py's _safe_nearest, the only real caller, which always passes
# an explicit kinds= tuple) storing a hash of the current reference-data
# seed set. Reused as a plain row in the existing url_vectors table
# instead of a new table, since it needs no schema beyond what's already
# there - `embedding` just gets a harmless all-zero placeholder.
_SEED_META_KIND = "_seed_meta"
_SEED_FINGERPRINT_KEY = "reference_data"


def _seed_fingerprint() -> str:
    """Stable hash over the current brand/phishing-pattern/scam-pattern
    seed data, so seed() can tell "Supabase already has today's
    reference data" apart from "seeded before this data last changed in
    code". A bare row COUNT can't tell those two apart if a label or
    pattern's text changes without the row count itself changing."""
    from bot.detectors.text.offline.scam_patterns import _seed_rows as _scam_pattern_rows

    payload = json.dumps(sorted(_brand_and_phish_rows() + _scam_pattern_rows()))
    return hashlib.sha256(payload.encode()).hexdigest()


async def _stored_seed_fingerprint(conn) -> str | None:
    cur = await conn.execute(
        "select label from url_vectors where kind = %s and key = %s",
        (_SEED_META_KIND, _SEED_FINGERPRINT_KEY),
    )
    row = await cur.fetchone()
    return row[0] if row else None


async def _mark_seeded(conn, fingerprint: str) -> None:
    await conn.execute(
        """
        insert into url_vectors (kind, key, label, embedding)
        values (%s, %s, %s, %s::vector)
        on conflict (kind, key) do update
        set label = excluded.label, added_at = now()
        """,
        (_SEED_META_KIND, _SEED_FINGERPRINT_KEY, fingerprint, [0.0] * DIM),
    )


async def seed() -> None:
    """Idempotently load brand vectors + synthetic phishing patterns +
    offline scam-message patterns (see scam_patterns.py) - as ONE
    batched write per source instead of 144+ individual upserts (see
    upsert_vectors_batch), and skipped ENTIRELY if Supabase already has
    this exact reference data (see _seed_fingerprint). This reference
    data is static Python source, only changing when a developer edits
    PROTECTED_BRANDS/PHISH_PATTERNS/SCAM_MESSAGE_PATTERNS - re-uploading
    the same 144+ rows on every single bot restart forever was real,
    measured, unnecessary cost (~28s cold, every time)."""
    from bot.detectors.text.offline import scam_patterns

    fingerprint = _seed_fingerprint()
    pool = await _get_pool()
    async with pool.connection() as conn:
        if await _stored_seed_fingerprint(conn) == fingerprint:
            return  # already seeded with today's data - nothing to do

    await asyncio.gather(
        upsert_vectors_batch(_brand_and_phish_rows()),
        scam_patterns.seed(),
    )

    async with pool.connection() as conn:
        await _mark_seeded(conn, fingerprint)


_seed_lock: asyncio.Lock | None = None
_seed_lock_loop: asyncio.AbstractEventLoop | None = None


def _get_seed_lock() -> asyncio.Lock:
    """A fresh asyncio.Lock per event loop instead of one shared
    module-level instance. asyncio.Lock only actually binds itself to a
    loop the first time it is CONTENDED (see CPython's
    _LoopBoundMixin/Lock.acquire fast path) - so a single shared lock
    works by accident right up until two callers genuinely race for it,
    at which point it permanently binds to whichever loop won that race.
    A later contender from a DIFFERENT loop then crashes with "Lock is
    bound to a different event loop." Harmless in production (one
    long-lived event loop for the whole process) but a real landmine for
    tests - pytest-asyncio gives each test its own fresh loop by
    default, and any test after the first one that genuinely contends
    this lock would fail non-deterministically depending on collection
    order, with an error that looks unrelated to the real cause.
    Confirmed via a standalone repro, not hypothetical.

    Safe to call from two "concurrent" callers on the same loop without
    creating two different locks: this function has no internal await,
    so asyncio's cooperative scheduling runs it to completion (through
    Lock.acquire()'s own uncontended fast path, itself sync/non-yielding)
    before any other coroutine on this loop gets a turn."""
    global _seed_lock, _seed_lock_loop
    loop = asyncio.get_running_loop()
    if _seed_lock is None or _seed_lock_loop is not loop:
        _seed_lock = asyncio.Lock()
        _seed_lock_loop = loop
    return _seed_lock


async def ensure_seeded(bot_data: dict) -> None:
    """Idempotent, crash-safe seeding for handlers to call instead of
    checking bot_data['_vectors_seeded'] and calling seed() directly.
    A Supabase outage here must never crash the calling handler - the
    same principle context_engine.py's _grounded_fallback already
    applies to its own vector lookup, now applied to seeding too. If
    seeding fails, don't mark it done - the next message simply retries.

    _seed_lock closes a real race, not a hypothetical one: right after
    a restart, EVERY handler (text/url/business) calls this before its
    real work, and a burst of messages arriving in that window (a
    queued backlog delivering all at once - confirmed live, seen
    repeatedly this session) would previously all see `_vectors_seeded`
    still unset and each launch their OWN full seed() - several
    concurrent 144+-row batch upserts competing for the pool's 5
    connections at once, a real, confirmed cause of the "Supabase pool
    exhausted" admin alerts. Double-checked locking: the flag check
    happens again AFTER acquiring the lock, so a caller that waited
    simply finds the work already done instead of redoing it."""
    if bot_data.get("_vectors_seeded"):
        return
    async with _get_seed_lock():
        if bot_data.get("_vectors_seeded"):
            return  # another concurrent caller already finished while we waited
        start = time.perf_counter()
        try:
            await seed()
            bot_data["_vectors_seeded"] = True
            logger.info("[first-message] Vector store seeded in %.3fs", time.perf_counter() - start)
        except Exception:                       # noqa: BLE001 - must never crash the calling handler
            logger.exception(
                "[first-message] Vector store seeding failed after %.3fs - will retry on next message",
                time.perf_counter() - start,
            )
