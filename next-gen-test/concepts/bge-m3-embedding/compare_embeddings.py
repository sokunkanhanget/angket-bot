"""
next-gen-test/concepts/bge-m3-embedding/compare_embeddings.py
================================================================
Sandbox prototype (NOT wired into the real bot) comparing the current
hashed n-gram embedding scheme (bot/url_checker/features/offline/
vectors.py's embed()/cosine()) against real embeddings from a local
Ollama bge-m3 model, specifically for `scam_pattern` (scam MESSAGE
text) matching - domain/link matching is explicitly out of scope for
this swap, since typosquat detection is character-level, not semantic
(see this session's discussion for why).

Ollama must be running locally with `bge-m3` pulled first:
    ollama pull bge-m3

Run from angket-bot/angket-bot/ (so bot.* imports resolve):
    PYTHONPATH=. python ../../next-gen-test/concepts/bge-m3-embedding/compare_embeddings.py
"""

from __future__ import annotations

import json
import math
import urllib.request

from bot.url_checker.features.offline import vectors
from bot.url_checker.features.offline.scam_patterns import SCAM_MESSAGE_PATTERNS

OLLAMA_URL = "http://localhost:11434/api/embeddings"
MODEL = "bge-m3"


def ollama_embed(text: str) -> list[float]:
    payload = json.dumps({"model": MODEL, "prompt": text}).encode()
    req = urllib.request.Request(OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())["embedding"]


def dense_cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def build_pattern_store():
    """Real pattern text -> (hashed sparse vector, bge-m3 dense vector)."""
    hashed = {}
    dense = {}
    for category, examples in SCAM_MESSAGE_PATTERNS.items():
        for i, text in enumerate(examples):
            key = f"{category}:{i}"
            hashed[key] = (category, vectors.embed(text))
            dense[key] = (category, ollama_embed(text))
    return hashed, dense


def nearest_hashed(hashed_store, text, k=1):
    q = vectors.embed(text)
    scored = [(vectors.cosine(q, vec), cat, key) for key, (cat, vec) in hashed_store.items()]
    scored.sort(reverse=True)
    return scored[:k]


def nearest_dense(dense_store, text, k=1):
    q = ollama_embed(text)
    scored = [(dense_cosine(q, vec), cat, key) for key, (cat, vec) in dense_store.items()]
    scored.sort(reverse=True)
    return scored[:k]


TEST_CASES = [
    (
        "Different wording, same scam (paraphrase - low character overlap)",
        "Mother, please wire funds immediately, I am stuck and cannot phone you right now, "
        "trust me on this and act fast.",
        "family_emergency",
    ),
    (
        "Khmer-language version of the same scam (cross-lingual - hashed scheme can't see this at all)",
        "ម៉ាក់ ខ្ញុំបាត់ទូរស័ព្ទ។ នេះជាលេខទូរស័ព្ទរបស់មិត្តភក្តិខ្ញុំ។ "
        "ខ្ញុំកំពុងជួបបញ្ហា។ សូមផ្ញើលុយមកខ្ញុំឥឡូវនេះ។ សូមកុំទូរស័ព្ទមក។",
        "family_emergency",
    ),
    (
        "Genuinely benign message (must NOT match any scam category)",
        "hey, are we still on for lunch tomorrow? let me know what time works",
        None,
    ),
]


def main():
    print("Seeding both schemes with the real SCAM_MESSAGE_PATTERNS...")
    hashed_store, dense_store = build_pattern_store()
    print(f"  {len(hashed_store)} pattern examples embedded with each scheme.\n")

    for title, text, expected_category in TEST_CASES:
        print(f"=== {title} ===")
        print(f"text: {text[:80]}{'...' if len(text) > 80 else ''}")

        h_sim, h_cat, h_key = nearest_hashed(hashed_store, text)[0]
        d_sim, d_cat, d_key = nearest_dense(dense_store, text)[0]

        print(f"  hashed n-gram scheme -> best match: {h_key} (category={h_cat}), similarity={h_sim:.3f}")
        print(f"  bge-m3 scheme        -> best match: {d_key} (category={d_cat}), similarity={d_sim:.3f}")

        if expected_category:
            h_correct = h_cat == expected_category and h_sim >= 0.5
            d_correct = d_cat == expected_category and d_sim >= 0.5
            print(f"  hashed correctly identifies '{expected_category}': {h_correct}")
            print(f"  bge-m3 correctly identifies '{expected_category}': {d_correct}")
        else:
            print(f"  hashed stays below 0.5 threshold (no false match): {h_sim < 0.5}")
            print(f"  bge-m3 stays below 0.5 threshold (no false match): {d_sim < 0.5}")
        print()


if __name__ == "__main__":
    main()
