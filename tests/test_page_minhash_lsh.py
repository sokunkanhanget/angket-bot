"""
tests/test_page_minhash_lsh.py
==============================
The banded lookup behind vectors.nearest_page().

nearest_page() used to load EVERY row of the page_minhash table and
compute MinHash similarity in Python one row at a time - linear in the
size of a table that only ever grows, on the hot path of every scan that
fetches a page (measured: 53ms at 10k rows, 307ms at 50k, 1138ms at
200k).

It now compares only against hosts sharing a whole MinHash band. The
point of these tests is that this is an EXACT prefilter, not the usual
approximate LSH: no pair at or above NEARDUP_THRESHOLD can be missed,
because a pair that similar mismatches on at most NUM_PERM -
ceil(threshold * NUM_PERM) positions, and NUM_BANDS is one greater than
that - so by pigeonhole at least one band is always byte-identical.
"""

import math
import random
import sqlite3
import struct

import pytest

from bot.detectors.url import pipeline
from bot.detectors.url.offline import vectors


@pytest.fixture
def page_db(tmp_path, monkeypatch):
    monkeypatch.setattr(vectors, "SCAN_LOG_DB", str(tmp_path / "pages.db"))
    return str(tmp_path / "pages.db")


def _random_signature(rng) -> bytes:
    return struct.pack(f"<{vectors.NUM_PERM}I",
                       *[rng.getrandbits(32) for _ in range(vectors.NUM_PERM)])


def _with_mismatches(sig: bytes, count: int, rng) -> bytes:
    """A copy of `sig` differing in exactly `count` positions, i.e. at
    similarity (NUM_PERM - count) / NUM_PERM."""
    values = list(struct.unpack(f"<{vectors.NUM_PERM}I", sig))
    for position in rng.sample(range(vectors.NUM_PERM), count):
        values[position] ^= 0xFFFFFFFF
    return struct.pack(f"<{vectors.NUM_PERM}I", *values)


def _full_scan(db: str, host: str, sig: bytes):
    """What the old unbounded implementation returned, for comparison."""
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute("select host, sig from page_minhash where host != ?",
                            (host.lower(),)).fetchall()
    finally:
        conn.close()
    best_host, best_sim = None, 0.0
    for other_host, other_sig in rows:
        sim = vectors.minhash_similarity(sig, other_sig)
        if sim > best_sim:
            best_host, best_sim = other_host, sim
    return (best_host, best_sim) if best_host else None


def _bulk_seed_random(db: str, count: int, rng) -> None:
    """Fill the table with unrelated signatures without paying
    store_page_signature's per-row connect/commit/minhash cost - these
    rows exist only as scan volume for the candidate-count assertions."""
    conn = sqlite3.connect(db)
    try:
        vectors._ensure_page_tables(conn)
        rows, band_rows = [], []
        for i in range(count):
            sig = _random_signature(rng)
            host = f"filler{i}.test"
            rows.append((host, sig, "2026-01-01"))
            band_rows.extend((key, host) for key in vectors._band_keys(sig))
        conn.executemany("insert or replace into page_minhash values (?, ?, ?)", rows)
        conn.executemany(
            "insert or ignore into page_minhash_bands(band_key, host) values (?, ?)", band_rows)
        conn.commit()
    finally:
        conn.close()


def _candidate_count(db: str, sig: bytes) -> int:
    conn = sqlite3.connect(db)
    try:
        keys = vectors._band_keys(sig)
        return conn.execute(
            f"select count(distinct host) from page_minhash_bands "
            f"where band_key in ({', '.join('?' * len(keys))})", keys
        ).fetchone()[0]
    finally:
        conn.close()


def test_lsh_band_count_is_exact_for_threshold():
    # The whole no-false-negatives guarantee rests on this one
    # inequality. Lowering NEARDUP_THRESHOLD (or raising NUM_PERM)
    # without raising NUM_BANDS would silently turn the exact prefilter
    # into an approximate one that drops real near-duplicate detections,
    # with nothing else in the suite noticing.
    min_matches = math.ceil(pipeline.NEARDUP_THRESHOLD * vectors.NUM_PERM)
    max_mismatches = vectors.NUM_PERM - min_matches
    assert vectors.NUM_BANDS >= max_mismatches + 1


def test_band_bounds_partition_every_position():
    bounds = vectors._band_bounds()
    assert len(bounds) == vectors.NUM_BANDS
    covered = [position for start, end in bounds for position in range(start, end)]
    assert covered == list(range(vectors.NUM_PERM))


def test_every_above_threshold_pair_is_still_found(page_db):
    # The pigeonhole guarantee, exercised directly: for every mismatch
    # count that still lands at or above NEARDUP_THRESHOLD, the banded
    # lookup must find the stored page. Random signatures, many seeds -
    # this is the test that would fail if NUM_BANDS were tuned the usual
    # probabilistic way.
    rng = random.Random(11)
    min_matches = math.ceil(pipeline.NEARDUP_THRESHOLD * vectors.NUM_PERM)
    max_mismatches = vectors.NUM_PERM - min_matches

    conn = sqlite3.connect(page_db)
    vectors._ensure_page_tables(conn)
    conn.commit()
    conn.close()

    for trial in range(40):
        stored = _random_signature(rng)
        host = f"stored-{trial}.test"
        conn = sqlite3.connect(page_db)
        conn.execute("insert into page_minhash values (?, ?, ?)", (host, stored, "2026-01-01"))
        conn.executemany("insert or ignore into page_minhash_bands(band_key, host) values (?, ?)",
                         [(key, host) for key in vectors._band_keys(stored)])
        conn.commit()
        conn.close()

        for mismatches in range(max_mismatches + 1):
            query = _with_mismatches(stored, mismatches, rng)
            similarity = vectors.minhash_similarity(query, stored)
            assert similarity >= pipeline.NEARDUP_THRESHOLD

            found = vectors.nearest_page("victim.test", query)
            assert found is not None, (
                f"banded lookup missed a pair at similarity {similarity:.4f}"
            )
            assert found[1] >= pipeline.NEARDUP_THRESHOLD


def test_finds_phishing_kit_near_duplicate_without_scanning_whole_table(page_db):
    # A real reused phishing kit: the same page text with one phrase
    # swapped. It must still be found, still score above
    # NEARDUP_THRESHOLD, and the lookup must compare against only a
    # handful of candidates rather than all 2000 stored rows.
    kit_page = (
        "Bank Security Notice. Your account will be suspended within 24 hours. "
        "Verify your information immediately using the secure form below to "
        "avoid permanent closure of your account. Enter your account number, "
        "password and the one-time code we sent to your phone."
    )
    copy_of_kit = kit_page.replace("within 24 hours", "within 48 hours")

    rng = random.Random(3)
    _bulk_seed_random(page_db, 5000, rng)
    vectors.store_page_signature("phish-kit-original.tk", kit_page)

    query_sig = vectors.minhash_signature(copy_of_kit)
    found = vectors.nearest_page("fresh-victim-domain.tk", query_sig)

    assert found is not None
    assert found[0] == "phish-kit-original.tk"
    assert found[1] >= pipeline.NEARDUP_THRESHOLD
    # 5000 rows stored, only a tiny candidate set actually compared -
    # the whole point of the band index.
    assert _candidate_count(page_db, query_sig) < 20


def test_banded_result_matches_the_old_full_scan_above_threshold(page_db):
    rng = random.Random(5)
    _bulk_seed_random(page_db, 300, rng)

    stored = _random_signature(rng)
    conn = sqlite3.connect(page_db)
    conn.execute("insert into page_minhash values (?, ?, ?)",
                 ("kit-host.tk", stored, "2026-01-01"))
    conn.executemany("insert or ignore into page_minhash_bands(band_key, host) values (?, ?)",
                     [(key, "kit-host.tk") for key in vectors._band_keys(stored)])
    conn.commit()
    conn.close()

    query_sig = _with_mismatches(stored, 4, rng)       # similarity 60/64 = 0.9375
    assert vectors.minhash_similarity(query_sig, stored) >= pipeline.NEARDUP_THRESHOLD

    assert vectors.nearest_page("asking.test", query_sig) == \
        _full_scan(page_db, "asking.test", query_sig)


def test_sub_threshold_matches_may_be_dropped_but_never_reach_a_verdict(page_db):
    # The honest limit of the exactness guarantee: it holds AT OR ABOVE
    # NEARDUP_THRESHOLD only. A pair further apart than that can be
    # filtered out by the banding, so nearest_page may return None where
    # the old full scan returned a real sub-threshold best match.
    #
    # That difference cannot change any verdict. pipeline.analyze_url's
    # only use of this function is guarded by
    # `if dup and dup[1] >= NEARDUP_THRESHOLD` - both the +25 score and
    # the reason/detail strings live inside that branch - so a
    # sub-threshold result is discarded either way, whether it arrives as
    # None or as a real tuple. This test pins that reasoning down so a
    # future caller that starts USING sub-threshold values has to come
    # here and confront it first.
    rng = random.Random(13)
    stored = _random_signature(rng)
    conn = sqlite3.connect(page_db)
    vectors._ensure_page_tables(conn)
    conn.execute("insert into page_minhash values (?, ?, ?)",
                 ("far-away.tk", stored, "2026-01-01"))
    conn.executemany("insert or ignore into page_minhash_bands(band_key, host) values (?, ?)",
                     [(key, "far-away.tk") for key in vectors._band_keys(stored)])
    conn.commit()
    conn.close()

    # 20 mismatches = 44/64 = 0.6875, well below the 0.90 threshold.
    query_sig = _with_mismatches(stored, 20, rng)
    full_scan_result = _full_scan(page_db, "asking.test", query_sig)
    assert full_scan_result is not None
    assert full_scan_result[1] < pipeline.NEARDUP_THRESHOLD

    banded = vectors.nearest_page("asking.test", query_sig)
    # Either answer is acceptable here; what matters is that neither one
    # clears the threshold the pipeline actually gates on.
    assert banded is None or banded[1] < pipeline.NEARDUP_THRESHOLD


def test_rescanning_a_host_drops_its_stale_band_rows(page_db):
    # A host that serves different content later must not stay indexed
    # under the bands of the page it used to serve, or it would keep
    # matching pages it no longer resembles at all.
    old_page = "The original page content about lottery prizes and winning numbers"
    vectors.store_page_signature("changes.test", old_page)
    stale_keys = vectors._band_keys(vectors.minhash_signature(old_page))

    new_page = "Completely different content about bus timetables in Phnom Penh"
    vectors.store_page_signature("changes.test", new_page)

    conn = sqlite3.connect(page_db)
    try:
        remaining = conn.execute(
            f"select count(*) from page_minhash_bands where host = ? and band_key in "
            f"({', '.join('?' * len(stale_keys))})", ("changes.test", *stale_keys)
        ).fetchone()[0]
        total = conn.execute("select count(*) from page_minhash_bands where host = ?",
                             ("changes.test",)).fetchone()[0]
    finally:
        conn.close()

    assert remaining == 0
    assert total == vectors.NUM_BANDS

    # And the old content is genuinely no longer findable via this host.
    assert vectors.nearest_page("someone-else.test", vectors.minhash_signature(old_page)) is None


def test_rows_written_before_the_band_index_existed_are_backfilled(page_db):
    # Every page signature already in a deployed database was written
    # before page_minhash_bands existed. Without a backfill they would be
    # invisible to the banded lookup - a silent loss of exactly the
    # historical pages this check exists to compare against.
    legacy_page = "Legacy stored page about urgent account verification and OTP codes"
    legacy_sig = vectors.minhash_signature(legacy_page)

    conn = sqlite3.connect(page_db)
    conn.execute("""create table page_minhash(host text primary key, sig blob not null,
                    checked_at text)""")
    conn.execute("insert into page_minhash values (?, ?, ?)",
                 ("legacy-host.tk", legacy_sig, "2026-01-01"))
    conn.commit()
    conn.close()

    found = vectors.nearest_page("new-scan.test",
                                 vectors.minhash_signature(legacy_page.replace("codes", "code")))

    assert found is not None
    assert found[0] == "legacy-host.tk"
    assert found[1] >= pipeline.NEARDUP_THRESHOLD
