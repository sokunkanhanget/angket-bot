"""
tests/test_scam_patterns.py
=============================
nearest_scam_pattern() is a local, in-memory search (no DB, no mocking
needed) - see scam_patterns.py's own docstring for why: the whole
SCAM_MESSAGE_PATTERNS corpus is ~17 static rows, too small to justify a
Supabase round trip every time it's consulted.
"""

from bot.detectors.text.scam_patterns import (
    SCAM_MESSAGE_PATTERNS,
    nearest_scam_pattern,
)
from bot.detectors.url.offline.vectors import embed


def test_nearest_scam_pattern_matches_a_near_exact_scam_script():
    text = ("Mom, this is urgent, I lost my phone and I'm texting from a friend's. "
            "I need you to send $800 right now to help me, don't call, just trust me "
            "on this one time.")

    hits = nearest_scam_pattern(text, k=1)

    assert hits[0][1] == "scam_pattern"
    assert hits[0][3] == "family_emergency"
    assert hits[0][0] >= 0.5


def test_nearest_scam_pattern_scores_benign_text_low():
    hits = nearest_scam_pattern("hey, are we still on for lunch tomorrow?", k=1)

    assert hits[0][0] < 0.3


def test_nearest_scam_pattern_returns_empty_for_empty_text():
    assert nearest_scam_pattern("", k=1) == []
    assert nearest_scam_pattern("!!!???...", k=1) == []


def test_nearest_scam_pattern_covers_every_seeded_category():
    # The local index must actually contain every category
    # SCAM_MESSAGE_PATTERNS defines, not a stale/partial copy.
    hits = nearest_scam_pattern(
        "This is the tax department, you owe unpaid taxes, pay immediately "
        "or a warrant will be issued for your arrest.", k=1,
    )
    assert hits[0][3] == "authority_impersonation"
    assert set(SCAM_MESSAGE_PATTERNS.keys()) == {
        "family_emergency", "lottery_prize", "account_verification",
        "romance", "investment_crypto", "job_offer", "authority_impersonation",
    }


def test_nearest_scam_pattern_respects_k():
    hits = nearest_scam_pattern("send money now urgent", k=3)
    assert len(hits) == 3
    # best-first
    assert hits[0][0] >= hits[1][0] >= hits[2][0]


def test_embed_produces_real_signal_for_khmer_only_text():
    # Regression: _TOKEN_RE used to be r"[a-z0-9]+" (ASCII-only), so a
    # pure-Khmer message tokenized to nothing and embed() returned {} -
    # not "low similarity", literally zero signal, for a Khmer-first
    # bot. This doesn't claim Khmer text now matches the (English-only)
    # SCAM_MESSAGE_PATTERNS corpus well - that's a real, separate,
    # larger cross-lingual limitation of this hashed scheme (see the
    # bge-m3 sandbox comparison). It only proves the embedding itself is
    # no longer degenerately empty for Khmer input.
    khmer_scam = "សូមផ្ញើលុយ ១០០ដុល្លារ ឥឡូវនេះ បន្ទាន់ណាស់"  # "please send $100 now, urgent"
    vec = embed(khmer_scam)
    assert vec != {}

    # Two different Khmer messages must produce different embeddings,
    # not the same degenerate fallback - proves this is real per-message
    # signal, not a constant.
    other_khmer = "អរគុណច្រើន សូមអញ្ជើញមកលេងផ្ទះខ្ញុំនៅចុងសប្តាហ៍នេះ"  # unrelated benign text
    assert embed(other_khmer) != vec


def test_nearest_scam_pattern_does_not_silently_short_circuit_on_khmer_text():
    # End-to-end: nearest_scam_pattern has an explicit `if not q: return []`
    # short-circuit for a genuinely empty query (e.g. "!!!???..." - see
    # test_nearest_scam_pattern_returns_empty_for_empty_text above). Before
    # the embed() fix, EVERY pure-Khmer message hit that same short-circuit
    # too - indistinguishable from actually-empty input. Now it must return
    # a real (possibly low-similarity, given the cross-lingual gap noted
    # above) scored result instead.
    hits = nearest_scam_pattern("សូមផ្ញើលុយ ១០០ដុល្លារ ឥឡូវនេះ បន្ទាន់ណាស់", k=1)
    assert len(hits) == 1
    assert 0.0 <= hits[0][0] <= 1.0
