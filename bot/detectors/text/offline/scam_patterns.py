"""
bot/detectors/text/scam_patterns.py
=====================================
Offline scam-MESSAGE pattern similarity - the deterministic fallback
signal used when Gemini is unavailable (see bot/context_engine/context_engine.py's
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

import asyncio
import logging

logger = logging.getLogger(__name__)

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


# --- bge-m3 (real, Khmer-capable embeddings) - live, with safe fallback --
# Gated by USE_BGE_M3_EMBEDDINGS (bot/config/config.py, default off - no
# production hosting is arranged yet, this depends on whatever Ollama
# instance OLLAMA_URL points at, which today means a local dev machine,
# not a reliable always-on server). ALWAYS falls back to the hashed
# scheme above on any failure (flag off, Ollama unreachable, a partial
# embedding failure) - callers get a usable result either way, never an
# exception, matching every other optional-backend pattern in this
# codebase (VirusTotal, Gemini).

_bge_m3_index: list[tuple[list[float], str, str]] | None = None
_bge_m3_index_lock = asyncio.Lock()


async def _ensure_bge_m3_index() -> bool:
    """Builds the bge-m3 embedding index for the same SCAM_MESSAGE_PATTERNS
    corpus the hashed _LOCAL_INDEX already covers, once, lazily (unlike
    the hashed index, this needs real Ollama round trips, so it's NOT
    built at import time). Returns True once the index is ready to use,
    False if it couldn't be built (Ollama unreachable) - a lock guards
    against two concurrent callers both trying to build it at once on
    the very first call."""
    global _bge_m3_index
    if _bge_m3_index is not None:
        return True

    from bot.detectors.text.online.bge_m3_embed import embed_bge_m3

    async with _bge_m3_index_lock:
        if _bge_m3_index is not None:  # someone else built it while we waited
            return True

        rows = _seed_rows()
        embeddings = await asyncio.gather(*(embed_bge_m3(text) for _, _, text, _ in rows))
        if any(e is None for e in embeddings):
            logger.warning("[bge-m3] index build failed (Ollama unreachable?) - "
                            "falling back to the hashed scheme")
            return False

        _bge_m3_index = [(emb, key, category) for emb, (_, key, _, category) in zip(embeddings, rows)]
        logger.info("[bge-m3] index built: %d scam-pattern examples", len(_bge_m3_index))
        return True


async def nearest_scam_pattern_live(text: str, k: int = 1) -> tuple[list[tuple[float, str, str, str]], bool]:
    """The real entry point for context_engine.py - prefers bge-m3 when
    enabled and reachable (genuinely Khmer-capable, unlike the hashed
    scheme - see bot/detectors/text/online/bge_m3_embed.py's module
    docstring for the measured gap), transparently falls back to the
    existing synchronous nearest_scam_pattern() otherwise.

    Returns (hits, used_bge_m3) - the second value matters because
    bge-m3 and the hashed scheme have DIFFERENT natural similarity
    scales (bge-m3 runs measurably hotter - confirmed live, genuinely
    benign text can score 0.59 - so the caller must compare against
    BGE_M3_PATTERN_THRESHOLD, not SCAM_PATTERN_THRESHOLD, when this is
    True). Found the hard way: an early version of this wiring reused
    the hashed scheme's threshold for both paths, which would have
    false-positived on ordinary benign messages once bge-m3 was live."""
    from bot.config.config import USE_BGE_M3_EMBEDDINGS
    from bot.detectors.text.online.bge_m3_embed import cosine_similarity, embed_bge_m3

    if USE_BGE_M3_EMBEDDINGS and await _ensure_bge_m3_index():
        query_embedding = await embed_bge_m3(text)
        if query_embedding is not None:
            scored = [
                (cosine_similarity(query_embedding, emb), "scam_pattern", key, category)
                for emb, key, category in _bge_m3_index
            ]
            scored.sort(key=lambda row: row[0], reverse=True)
            return scored[:k], True
        logger.warning("[bge-m3] query embedding failed - falling back to the hashed scheme for this call")

    return nearest_scam_pattern(text, k), False
