"""
bot/detectors/text/online/bge_m3_embed.py
=============================================
Real bge-m3 embeddings via a local Ollama instance - PREPARED, not
wired into the live query path yet (see USE_BGE_M3_EMBEDDINGS in
bot/config.py, default off). Production hosting (Daun Penh Data Center
or equivalent always-on Ollama) hasn't been arranged - this points at
a local dev Ollama by default, which is not a production dependency.

Why this exists: the current offline scam-pattern matching
(bot/detectors/text/offline/scam_patterns.py) uses hashed sparse
n-gram embeddings that are completely blind to Khmer text (confirmed
in an earlier session: 0.000 similarity on every Khmer test case,
not just weak - the tokenizer only matched ASCII word characters
until a partial fix). bge-m3 is a real multilingual embedding model
that handles Khmer natively; a sandbox comparison
(next-gen-test/concepts/bge-m3-embedding/) validated it across 54
test cases with a stable 0.049 similarity gap between scam and
benign messages, including hard Khmer-only and money+urgency cases.

What's genuinely done here: a real, tested function that calls a real
Ollama instance and gets a real embedding back, plus real cosine
similarity math. What's NOT done: swapping scam_patterns.py's
nearest_scam_pattern() over to use this live - that function is
currently synchronous and called synchronously from several places
(context_engine.py's analyze_unified/_grounded_fallback); making it
call this async function would mean making nearest_scam_pattern
itself async and updating every call site, a real activation step
appropriately deferred until production hosting actually exists, not
a "preparation" change.
"""

from __future__ import annotations

import math

import httpx

from bot.config import OLLAMA_URL

EMBED_MODEL = "bge-m3"
TIMEOUT_SECONDS = 10.0


async def embed_bge_m3(text: str) -> list[float] | None:
    """Real embedding via Ollama's /api/embeddings endpoint. Returns
    None on ANY failure (Ollama not running, model not pulled, network
    down, etc.) - callers must treat this as "unavailable, fall back to
    the existing hashed scheme", never crash on it. Matches this
    codebase's established pattern for every other optional backend
    (VirusTotal, Gemini) degrading gracefully rather than raising."""
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
            response = await client.post(
                f"{OLLAMA_URL}/api/embeddings",
                json={"model": EMBED_MODEL, "prompt": text},
            )
            response.raise_for_status()
            embedding = response.json().get("embedding")
            return embedding if embedding else None
    except Exception:                          # noqa: BLE001 - unavailable embedding source must degrade, not crash
        return None


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Plain cosine similarity over two dense vectors - bge-m3's real
    output isn't pre-normalized the way vectors.py's hashed scheme is,
    so this divides by both norms rather than assuming a dot product
    alone is enough."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)
