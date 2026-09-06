"""
tests/conftest.py
===================
Shared fixtures. The url_vectors similarity store moved from SQLite to
Supabase Postgres+pgvector (see bot/detectors/url/offline/vectors.py) -
a real, shared, external database, so the old "isolate to a tmp_path
SQLite file" strategy no longer applies (there's no per-test local file
to isolate to, and hitting the real network from the offline unit suite
would be slow, flaky, and pollute shared data).

`seeded_vectors` replaces that isolation with an in-memory fake store
that implements the exact same async contract (upsert_vector/nearest)
using the REAL, unchanged embed()/cosine() math - so tests still get a
genuine write-then-read round trip (this matters: several tests are
specifically about vector-memory behavior, e.g. "a flagged link is
remembered" / "a lookalike link matches it later") without any network
dependency. `seed()` is reimplemented against the fake store the same
way, from the same real PROTECTED_BRANDS/PHISH_PATTERNS/SCAM_MESSAGE_PATTERNS
seed data the real seed() uses.
"""

import pytest
import pytest_asyncio

from bot.detectors.url.offline import vectors
from bot.storage import scan_log
from bot.storage import subscription


class _FakeVectorStore:
    """In-memory stand-in for the Postgres url_vectors table."""

    def __init__(self):
        self.rows: dict[tuple[str, str], tuple[str | None, dict[int, float]]] = {}

    async def upsert_vector(self, kind: str, key: str, text: str, label: str | None = None) -> None:
        self.rows[(kind, key.lower())] = (label, vectors.embed(text))

    async def nearest(self, text: str, k: int = 3, kinds: tuple[str, ...] | None = None):
        q = vectors.embed(text)
        if not q:
            return []
        scored = []
        for (kind, key), (label, vec) in self.rows.items():
            if kinds and kind not in kinds:
                continue
            scored.append((vectors.cosine(q, vec), kind, key, label))
        scored.sort(key=lambda t: t[0], reverse=True)
        return scored[:k]

    async def seed(self) -> None:
        # Sourced from the SAME row-building helpers the real seed()
        # uses (vectors._brand_and_phish_rows / scam_patterns._seed_rows)
        # instead of a hand-duplicated copy of PROTECTED_BRANDS/
        # PHISH_PATTERNS/SCAM_MESSAGE_PATTERNS - so this fake can't
        # silently drift from what production actually seeds.
        from bot.detectors.text.offline import scam_patterns

        for kind, key, text, label in vectors._brand_and_phish_rows() + scam_patterns._seed_rows():
            await self.upsert_vector(kind, key, text, label)


@pytest.fixture
def fake_vector_store(monkeypatch):
    """Patches every import site of upsert_vector/nearest with the fake
    store. Returns the store itself for tests that want to poison/inspect
    it directly (e.g. simulating corrupted memory)."""
    store = _FakeVectorStore()

    monkeypatch.setattr(vectors, "upsert_vector", store.upsert_vector)
    monkeypatch.setattr(vectors, "nearest", store.nearest)
    monkeypatch.setattr(vectors, "seed", store.seed)

    # context_engine.py's scam-pattern lookup (nearest_scam_pattern, in
    # scam_patterns.py) is a LOCAL in-memory search over the real
    # SCAM_MESSAGE_PATTERNS data - it never touches url_vectors (fake or
    # real) at all, so there's nothing to patch for it here.

    return store


@pytest_asyncio.fixture
async def seeded_vectors(fake_vector_store, tmp_path, monkeypatch):
    """Same name/shape tests already use - now backed by the in-memory
    fake instead of a real SQLite tmp file for url_vectors specifically,
    already seeded. Still isolates the SQLite-backed pieces that DIDN'T
    move (MinHash page dedup, domain-age cache, and pipeline.py's
    exact-match link-verdict cache) to a tmp file, exactly like the old
    fixture did - only the url_vectors table's backend changed, not
    whether SQLite-touching tests should hit the real scan_logs.db.
    Without patching pipeline.SCAN_LOG_DB too, an earlier test in the
    same run could cache a URL's verdict for real, and a later test
    reusing that same URL would get a stale cache hit instead of
    exercising the code it meant to test."""
    db = str(tmp_path / "test_scan.db")
    monkeypatch.setattr(vectors, "SCAN_LOG_DB", db)
    monkeypatch.setattr("bot.detectors.url.online.domain_info.SCAN_LOG_DB", db)
    monkeypatch.setattr("bot.detectors.url.pipeline.SCAN_LOG_DB", db)

    await fake_vector_store.seed()
    return fake_vector_store


@pytest.fixture(scope="session", autouse=True)
def isolated_scan_log_db(tmp_path_factory):
    """bot.storage.scan_log does its own `from bot.config import SCAN_LOG_DB`,
    binding a SEPARATE module-level name from the copies pipeline.py/
    domain_info.py/cert_info.py/vectors.py each bind the same way - so
    seeded_vectors patching THOSE never touches this one. Nothing else in
    the suite isolates it, so any test whose code path reaches
    log_scan()/log_url_scan() (e.g. handle_business_message, once a link or
    file verdict comes back) falls through to whatever real scan_logs.db
    happens to sit in the repo root/cwd - which may be missing the
    url_scan_logs table entirely (exactly the "no such table" failure this
    fixture exists to prevent), or worse, silently write real rows into a
    developer's local db. autouse so every test gets an isolated db with
    both tables already created via init_db()/init_url_db(), matching the
    isolate-and-initialize pattern used for every sibling SQLite-backed
    piece in this file - whether or not a given test explicitly asks for
    it.

    Session-scoped (not per-test): init_db()/init_url_db() are idempotent
    `CREATE TABLE IF NOT EXISTS` calls and no test in the suite asserts on
    scan-log row counts or otherwise depends on the tables starting empty
    per test, so re-running the same init 191 times bought nothing but
    ~4s of real sqlite3.connect()-to-a-new-file overhead. Plain attribute
    assignment instead of monkeypatch since monkeypatch itself is
    function-scoped and can't back a session-scoped fixture; there's
    nothing to restore since no other real value should ever fill this
    slot inside a test run.
    """
    db = str(tmp_path_factory.mktemp("scan_log") / "test_scan_log.db")
    scan_log.SCAN_LOG_DB = db
    scan_log.init_db()
    scan_log.init_url_db()
    # subscription.py binds SCAN_LOG_DB the same separate way - same
    # isolation gap this fixture already exists to close for scan_log.py.
    subscription.SCAN_LOG_DB = db
    return db


@pytest.fixture(scope="session")
def _subscription_reset_conn(isolated_scan_log_db):
    """One connection, opened once and reused for the whole session -
    a fresh sqlite3.connect() per test (231 of them) measurably regressed
    suite time (~5s -> ~12s) the same way a per-test scan_log connection
    already did once this session, fixed the same way: keep one
    connection alive and reuse it, since the actual isolation only needs
    the cheap DELETEs below, not a fresh connection each time."""
    conn = subscription._connect()
    yield conn
    conn.close()


@pytest.fixture(autouse=True)
def _reset_subscription_usage(_subscription_reset_conn):
    """Per-test (unlike the session-scoped fixture above): many existing
    handler tests reuse the same hardcoded fake user id (e.g.
    test_file_handler.py's _file_update() always defaults to id=7)
    across several tests in the same file. Since daily_usage/trial_status
    live in the same session-scoped db, an earlier test's real recorded
    usage (record_file_scan, etc.) would otherwise carry over and trip a
    later, unrelated test's rate-limit check unexpectedly."""
    _subscription_reset_conn.execute("delete from daily_usage")
    _subscription_reset_conn.execute("delete from trial_status")
    _subscription_reset_conn.commit()
