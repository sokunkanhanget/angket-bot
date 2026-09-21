"""
bot/detectors/text/online/bge_m3_embed.py
=============================================
Real bge-m3 embeddings - live in production as of 2026-09-21, wired into
bot/detectors/text/offline/scam_patterns.py's nearest_scam_pattern_live()
(gated by USE_BGE_M3_EMBEDDINGS in bot/config/config.py). Hosting was the
real blocker for a long time (no free-tier VM with enough RAM could be
provisioned - Oracle/GCP signup both hit real, unresolved account-
verification walls) - resolved by hosting on Modal (serverless, free
tier, no card required) instead of a local/self-managed Ollama instance.
See next-gen-test/concepts/modal-bge-m3/modal_bge_m3.py for the actual
deployment - it mirrors Ollama's own POST /api/embeddings request/
response shape exactly, so this file needed zero code changes beyond
OLLAMA_URL pointing at the Modal deployment's URL instead of a local
Ollama instance, and TIMEOUT_SECONDS raised (see below) to tolerate real
Modal cold-start latency.

Why this exists: the current offline scam-pattern matching
(bot/detectors/text/offline/scam_patterns.py) uses hashed sparse
n-gram embeddings that are completely blind to Khmer text (confirmed
in an earlier session: 0.000 similarity on every Khmer test case,
not just weak - the tokenizer only matched ASCII word characters
until a partial fix). bge-m3 is a real multilingual embedding model
that handles Khmer natively; a sandbox comparison
(next-gen-test/concepts/bge-m3-embedding/) validated it across 54
test cases with a stable 0.049 similarity gap between scam and
benign messages, including hard Khmer-only and money+urgency cases -
that validation, and BGE_M3_PATTERN_THRESHOLD's calibration, both stay
valid after this hosting change since the model itself is unchanged,
only where it runs.
"""

from __future__ import annotations

import math

import httpx

from bot.config.config import OLLAMA_URL

EMBED_MODEL = "bge-m3"
# 30s, not 10s (2026-09-21): now hosted on Modal (see next-gen-test/
# concepts/modal-bge-m3/), not local Ollama - a cold-starting container
# loading bge-m3 for the first time can genuinely take longer than a
# local-loopback call ever would, especially under _ensure_bge_m3_index's
# concurrent asyncio.gather burst of ~20 simultaneous calls on first use.
TIMEOUT_SECONDS = 30.0


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
