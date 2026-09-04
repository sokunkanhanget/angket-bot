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
        from bot.detectors.url.offline.lexical import PROTECTED_BRANDS
        from bot.detectors.text import scam_patterns

        for domain, label in PROTECTED_BRANDS.items():
            await self.upsert_vector("brand", domain, domain, label)

        for domain, label in PROTECTED_BRANDS.items():
            brand = domain.split(".")[0]
            for pattern in vectors.PHISH_PATTERNS:
                fake = pattern.format(brand=brand)
                await self.upsert_vector("phish", fake, fake, f"{label} impersonation pattern")

        for category, examples in scam_patterns.SCAM_MESSAGE_PATTERNS.items():
            for i, t in enumerate(examples):
                await self.upsert_vector("scam_pattern", f"{category}:{i}", t, category)


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
