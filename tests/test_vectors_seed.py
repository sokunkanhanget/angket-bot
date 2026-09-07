"""
tests/test_vectors_seed.py
============================
Direct unit coverage for the pure (no-DB) parts of the seed()
batching/skip-if-already-seeded rework: row-building and the content
fingerprint used to decide whether Supabase already has today's
reference data. The DB-touching half (upsert_vectors_batch,
_stored_seed_fingerprint, _mark_seeded) isn't unit-tested directly here,
same as upsert_vector/nearest never were - real behavior is exercised
via tests/conftest.py's fake vector store instead.
"""

import pytest

from bot.detectors.text.offline import scam_patterns
from bot.detectors.url.offline import vectors
from bot.detectors.url.offline.lexical import PROTECTED_BRANDS


def test_brand_and_phish_rows_covers_every_brand_and_pattern():
    rows = vectors._brand_and_phish_rows()
    brand_rows = [r for r in rows if r[0] == "brand"]
    phish_rows = [r for r in rows if r[0] == "phish"]

    # brand_rows: one per PROTECTED_BRANDS domain, even brands that share
    # a name root across more than one real domain (telegram.org/
    # telegram.me/t.me) - each domain still gets its own "brand" vector
    # so similarity search can match against ALL of a brand's real
    # domains, not just its canonical one.
    assert len(brand_rows) == len(PROTECTED_BRANDS)
    # phish_rows: one per UNIQUE brand_name root x PHISH_PATTERNS, not
    # per domain - a brand with multiple real domains sharing the same
    # root (e.g. "telegram" from both telegram.org and telegram.me)
    # would otherwise generate byte-identical duplicate synthetic
    # phishing patterns, which is wasted seed data, not extra coverage.
    unique_brand_names = {domain.split(".")[0] for domain in PROTECTED_BRANDS}
    assert len(phish_rows) == len(unique_brand_names) * len(vectors.PHISH_PATTERNS)
    # Every row has a real (kind, key, text, label) shape - no Nones snuck
    # in that would make json.dumps sorting blow up in _seed_fingerprint.
    for kind, key, text, label in rows:
        assert kind and key and text and label


def test_scam_pattern_seed_rows_covers_every_example():
    rows = scam_patterns._seed_rows()
    expected = sum(len(examples) for examples in scam_patterns.SCAM_MESSAGE_PATTERNS.values())
    assert len(rows) == expected
    assert all(kind == "scam_pattern" for kind, *_ in rows)


def test_seed_fingerprint_is_deterministic():
    assert vectors._seed_fingerprint() == vectors._seed_fingerprint()


def test_seed_fingerprint_changes_when_brand_data_changes(monkeypatch):
    before = vectors._seed_fingerprint()

    monkeypatch.setattr(
        "bot.detectors.url.offline.lexical.PROTECTED_BRANDS",
        {**PROTECTED_BRANDS, "totally-new-brand.com": "New Brand"},
    )
    after = vectors._seed_fingerprint()

    assert before != after


def test_seed_fingerprint_changes_when_scam_pattern_data_changes(monkeypatch):
    before = vectors._seed_fingerprint()

    monkeypatch.setattr(
        "bot.detectors.text.offline.scam_patterns.SCAM_MESSAGE_PATTERNS",
        {**scam_patterns.SCAM_MESSAGE_PATTERNS, "new_category": ["a brand new scam script"]},
    )
    after = vectors._seed_fingerprint()

    assert before != after


@pytest.mark.asyncio
async def test_fake_vector_store_seed_matches_real_row_count(fake_vector_store):
    await fake_vector_store.seed()
    expected = len(vectors._brand_and_phish_rows()) + len(scam_patterns._seed_rows())
    assert len(fake_vector_store.rows) == expected
