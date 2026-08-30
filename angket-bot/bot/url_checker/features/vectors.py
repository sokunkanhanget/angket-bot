"""
bot/url_checker/features/vectors.py
=====================================
Vector search over links and page text, backed by SQLite.

This is the mentor-suggested "vector search with a database" piece:

  * `embed()` turns any string (URL syntax, page title/text) into a
    fixed-length sparse numeric vector using feature hashing of word
    tokens + character n-grams. No ML model needed, works offline,
    and captures enough signal that "ababank-secure-login.tk" lands
    close to known phishing patterns while "ababank.com" sits next to
    the official brand vectors.

  * Vectors are L2-normalized so COSINE SIMILARITY is a plain dot
    product. Stored as compact BLOBs in the same scan_log DB.

  * `nearest()` does brute-force k-NN — perfectly fine at bot scale
    (tens of thousands of rows). If this ever grows past that, swap
    the query loop for sqlite-vec / Faiss; the schema and embed()
    stay identical.

Also implements MinHash-LSH for near-duplicate PAGE detection: two
phishing kits served from different hosts produce nearly identical
HTML, so matching MinHash signatures flags them without scanning the
full body again. Same idea the research notes call LSH.
"""

from __future__ import annotations

import hashlib
import re
import struct
import sqlite3
import time

from bot.config import SCAN_LOG_DB

# --- Embedding -------------------------------------------------------

DIM = 256          # vector dimensionality
NGRAM = 4          # character n-gram size
_TOKEN_RE = re.compile(r"[a-z0-9]+")

LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _hash_token(token: str):
    """Signed hashing: one positive/negative bucket index per token."""
    digest = hashlib.md5(token.encode("utf-8")).digest()
    idx = int.from_bytes(digest[:4], "little") % DIM
    sign = 1 if digest[4] % 2 == 0 else -1
    return idx, sign


def embed(text: str) -> dict[int, float]:
    """Sparse hashed embedding: word tokens + char n-grams, de-leeted."""
    text = (text or "").lower().translate(LEET_MAP)
    vec: dict[int, float] = {}

    def _add(token: str, weight: float = 1.0):
        idx, sign = _hash_token(token)
        vec[idx] = vec.get(idx, 0.0) + sign * weight

    for token in _TOKEN_RE.findall(text):
        if len(token) >= 2:
            _add("w:" + token, 1.0)
        padded = f"^{token}$"
        for i in range(len(padded) - NGRAM + 1):
            _add("c:" + padded[i:i + NGRAM], 0.5)

    norm = sum(v * v for v in vec.values()) ** 0.5
    if norm == 0:
        return {}
    return {i: v / norm for i, v in vec.items()}


def cosine(a: dict[int, float], b: dict[int, float]) -> float:
    """Both vectors are L2-normalized, so cosine = dot product."""
    if not a or not b:
        return 0.0
    if len(b) < len(a):
        a, b = b, a
    return sum(v * b.get(i, 0.0) for i, v in a.items())


# --- Serialization ----------------------------------------------------

def _pack(vec: dict[int, float]) -> bytes:
    return b"".join(struct.pack("<if", i, v) for i, v in sorted(vec.items()))


def _unpack(blob: bytes) -> dict[int, float]:
    vec = {}
    for off in range(0, len(blob), 8):
        i, v = struct.unpack_from("<if", blob, off)
        vec[i] = v
    return vec


# --- SQLite-backed k-NN -----------------------------------------------

def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(SCAN_LOG_DB)
    conn.execute(
        """
        create table if not exists url_vectors(
            id integer primary key autoincrement,
            kind text not null,          -- 'brand' | 'phish' | 'seen'
            key text not null unique,    -- domain or url the vector represents
            label text,                  -- human name, e.g. 'ABA Bank'
            vec blob not null,
            added_at text
        )
        """
    )
    return conn


def upsert_vector(kind: str, key: str, text: str, label: str | None = None) -> None:
    """Store/refresh the embedding of one URL or brand profile."""
    conn = _connect()
    try:
        conn.execute(
            "insert or replace into url_vectors(kind, key, label, vec, added_at) values (?, ?, ?, ?, ?)",
            (kind, key.lower(), label, _pack(embed(text)),
             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        )
        conn.commit()
    finally:
        conn.close()


def nearest(text: str, k: int = 3, kinds: tuple[str, ...] | None = None):
    """k most similar stored vectors to `text` -> [(similarity, kind, key, label)]."""
    q = embed(text)
    if not q:
        return []
    conn = _connect()
    try:
        rows = conn.execute("select kind, key, label, vec from url_vectors").fetchall()
    finally:
        conn.close()
    scored = []
    for kind, key, label, blob in rows:
        if kinds and kind not in kinds:
            continue
        scored.append((cosine(q, _unpack(blob)), kind, key, label))
    scored.sort(key=lambda t: t[0], reverse=True)
    return scored[:k]


# --- MinHash-LSH for near-duplicate pages -----------------------------

NUM_PERM = 64


def minhash_signature(text: str) -> bytes:
    """64-permutation MinHash signature of shingles, packed as BLOB."""
    text = re.sub(r"\s+", " ", (text or "").lower())
    shingles = {text[i:i + 8] for i in range(0, max(len(text) - 7, 1))}
    if not shingles:
        return b"\x00" * (NUM_PERM * 4)
    sig = []
    for p in range(NUM_PERM):
        minimum = min(
            int.from_bytes(hashlib.md5((str(p) + s).encode()).digest()[:4], "little")
            for s in shingles
        )
        sig.append(minimum)
    return struct.pack(f"<{NUM_PERM}I", *sig)


def minhash_similarity(sig_a: bytes, sig_b: bytes) -> float:
    if not sig_a or len(sig_a) != len(sig_b):
        return 0.0
    matches = sum(1 for a, b in zip(struct.unpack(f"<{NUM_PERM}I", sig_a),
                                    struct.unpack(f"<{NUM_PERM}I", sig_b)) if a == b)
    return matches / NUM_PERM


def store_page_signature(host: str, page_text: str) -> bytes:
    """Save a page's MinHash under its host; returns the signature."""
    sig = minhash_signature(page_text)
    conn = _connect()
    try:
        conn.execute(
            """
            create table if not exists page_minhash(
                host text primary key,
                sig blob not null,
                checked_at text
            )
            """
        )
        conn.execute(
            "insert or replace into page_minhash(host, sig, checked_at) values (?, ?, ?)",
            (host.lower(), sig, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        )
        conn.commit()
    finally:
        conn.close()
    return sig


def nearest_page(host: str, sig: bytes) -> tuple[str, float] | None:
    """Closest stored page signature to `sig`, excluding `host` itself."""
    conn = _connect()
    try:
        rows = conn.execute("select host, sig from page_minhash where host != ?", (host.lower(),)).fetchall()
    finally:
        conn.close()
    best_host, best_sim = None, 0.0
    for other_host, other_sig in rows:
        sim = minhash_similarity(sig, other_sig)
        if sim > best_sim:
            best_host, best_sim = other_host, sim
    return (best_host, best_sim) if best_host else None


# --- Seed data --------------------------------------------------------

PHISH_PATTERNS = [
    "{brand}-secure-login.verify-account.tk",
    "{brand}.support-team.cf",
    "login.{brand}.verify-user.ml",
    "{brand}-wallet-connect.ga",
    "{brand}.account-suspended.gq",
    "secure{brand}.com",
    "{brand}-update-billing.info",
]


def seed() -> None:
    """Idempotently load brand vectors + synthetic phishing patterns."""
    from bot.url_checker.features.lexical import PROTECTED_BRANDS

    for domain, label in PROTECTED_BRANDS.items():
        upsert_vector("brand", domain, domain, label)

    for domain, label in PROTECTED_BRANDS.items():
        brand = domain.split(".")[0]
        for pattern in PHISH_PATTERNS:
            fake = pattern.format(brand=brand)
            upsert_vector("phish", fake, fake, f"{label} impersonation pattern")

