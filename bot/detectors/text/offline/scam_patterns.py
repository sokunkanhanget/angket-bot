"""
bot/detectors/text/scam_patterns.py
=====================================
Offline scam-MESSAGE pattern similarity - the deterministic fallback
signal used when Gemini is unavailable (see bot/context_engine.py's
_grounded_fallback), AND (see nearest_scam_pattern below) a piece of
evidence fed into the live Gemini call too.

Lives under detectors/text/ (not detectors/url/) because this compares
MESSAGE TEXT against known scam scripts, not URLs - it shares
vectors.py's embedding/cosine machinery (imported from
detectors/url/offline/vectors.py below) purely for infrastructure reuse
(same hashed-embedding scheme, same vector store), not because this is
URL-domain logic.

This is deliberately separate from vectors.py's existing "phish" pool:
that pool is seeded with DOMAIN-shaped strings
("aba-secure-login.verify-account.tk") built to compare against URLs.
A natural-language scam message ("Mom, this is urgent, send $800 now,
don't call") has a completely different structural signature - character
n-grams and word tokens for a sentence don't land anywhere near a
domain's n-grams, so comparing message text against the domain-pattern
pool doesn't work. This module seeds a SEPARATE vector kind
('scam_pattern') with representative example sentences for well-known
scam categories, so nearest() can compare a message against message-shaped
examples instead.

These are widely-documented, generic scam categories used in consumer-
protection / security-awareness material everywhere (FTC, banks,
telecoms) - hand-written representative examples, not scraped from any
real conversation, same spirit as vectors.py's own PHISH_PATTERNS
templates for domains.
"""

from __future__ import annotations

SCAM_MESSAGE_PATTERNS: dict[str, list[str]] = {
    "family_emergency": [
        "Mom, I lost my phone, this is my friend's number. I'm in trouble and need money right now, please don't call, just trust me.",
        "Grandma, it's me, I've been in an accident and need bail money urgently, please don't tell mom and dad.",
        "This is your brother, I'm stuck abroad and lost my wallet, can you wire money immediately, I'll explain later.",
    ],
    "lottery_prize": [
        "Congratulations! You've been selected as our lucky winner of a large cash prize. Claim your prize now by sending your bank details.",
        "You have won a free phone! Click here to claim before it expires today.",
        "Your number has been selected in our anniversary promotion, contact us with your ID to receive your reward.",
    ],
    "account_verification": [
        "Your account will be suspended in 24 hours unless you verify your information immediately.",
        "We detected unusual activity on your account. Reply with your OTP code now to secure it.",
        "Your subscription payment failed, update your billing information now to avoid service interruption.",
    ],
    "romance": [
        "I really care about you, but I'm stuck at customs and need money to release my luggage, can you help me, my love?",
        "I want to visit you but I don't have enough for the plane ticket, could you send some money?",
    ],
    "investment_crypto": [
        "I made a lot of money in one week with this trading platform, join now with a small deposit and I'll show you how.",
        "Double your crypto in 24 hours guaranteed, limited slots available, invest now.",
    ],
    "job_offer": [
        "You are hired for a work from home job paying great money per day, just send your bank details to get started today.",
        "Congratulations, you passed our interview, please pay a small registration fee to start work immediately.",
    ],
    "authority_impersonation": [
        "This is the tax department, you owe unpaid taxes, pay immediately or a warrant will be issued for your arrest.",
        "Your account has been flagged for illegal activity, contact us immediately or you will be reported to the police.",
    ],
}


def _seed_rows() -> list[tuple[str, str, str, str | None]]:
    """The (kind, key, text, label) rows seed() writes - pure, no DB
    access, so vectors.py's fingerprint check (and tests) can use the
    exact same row set without needing a real connection."""
    return [
        ("scam_pattern", f"{category}:{i}", text, category)
        for category, examples in SCAM_MESSAGE_PATTERNS.items()
        for i, text in enumerate(examples)
    ]


async def seed() -> None:
    """Idempotently load scam-message pattern vectors (kind='scam_pattern')
    as ONE batched write instead of one round trip per example."""
    from bot.detectors.url.offline.vectors import upsert_vectors_batch

    await upsert_vectors_batch(_seed_rows())


# --- Local, in-memory search (no Supabase round trip) -------------------
# The whole SCAM_MESSAGE_PATTERNS corpus is ~17 hand-written examples,
# static at runtime (only changes when a developer edits this file and
# re-seeds) - far too small to justify a real DB query every time it's
# consulted. seed() above still pushes these into Supabase too, so the
# SAME patterns remain visible to pipeline.py's own nearest() calls
# (which query across kinds, including 'scam_pattern', for other
# purposes) - this local index is an ADDITIONAL, faster path for the two
# scam-message-specific callers (context_engine.py's live path and
# fallback), not a replacement for the DB rows.
#
# Built once at import time, not lazily: embed() is pure computation, no
# I/O, and 17 calls to it is sub-millisecond - there's no cold-start cost
# worth deferring.

def _build_local_index() -> list[tuple[str, str, dict[int, float]]]:
    from bot.detectors.url.offline.vectors import embed

    return [
        (f"{category}:{i}", category, embed(text))
        for category, examples in SCAM_MESSAGE_PATTERNS.items()
        for i, text in enumerate(examples)
    ]


_LOCAL_INDEX = _build_local_index()


def nearest_scam_pattern(text: str, k: int = 1) -> list[tuple[float, str, str, str]]:
    """Same return shape as vectors.nearest() - (similarity, kind, key,
    label) tuples, sorted best-first - so callers don't need to know
    this isn't the DB-backed search. Brute-force over ~17 rows is not
    just fast, it's EXACT (the DB path uses pgvector's HNSW index, which
    is itself an approximate search) - this trades nothing for the
    speed, unlike a real accuracy-for-speed compromise would."""
    from bot.detectors.url.offline.vectors import cosine, embed

    q = embed(text)
    if not q:
        return []
    scored = [
        (cosine(q, vec), "scam_pattern", key, category)
        for key, category, vec in _LOCAL_INDEX
    ]
    scored.sort(key=lambda row: row[0], reverse=True)
    return scored[:k]
