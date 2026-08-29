"""
bot/linkchecker/pipeline.py
============================
The full link-checking pipeline — orchestrates every signal source
into one verdict per URL:

    lexical (lexical.py, sync, instant)
      + network trace  (network.py, async)        \
      + DNS + domain age (domain_info.py, async)  /  run concurrently
      + vector similarity vs brand/phish vectors (vectors.py)
      + MinHash near-duplicate page match        (vectors.py)
      + re-score of the FINAL landing URL after redirects

Score contributions are capped per family so no single category can
alone push a URL to "dangerous", and every added point comes with a
plain-language reason for the Telegram breakdown.

The verdict dict keeps the exact shape url_handler already renders
(raw/host/score/level/reasons/emoji/label) plus an optional
`detail` list of extra technical lines shown in the full breakdown.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlsplit

from bot.linkchecker import network, vectors
from bot.linkchecker import threat_intel
from bot.linkchecker.domain_info import domain_age_days, resolve_host, score_domain_age
from bot.linkchecker.lexical import (
    PROTECTED_BRANDS,
    _verdict_labels,
    check_url,
    extract_urls,
    registered_domain,
)
from bot.config import VIRUSTOTAL_API_KEY

logger = logging.getLogger(__name__)

# Thresholds & caps ----------------------------------------------------

PHISH_SIM_THRESHOLD = 0.55     # cosine vs known-phish pattern worth flagging
PHISH_SIM_STRONG = 0.80        # near-certain impersonation
SEEN_BAD_SIM_THRESHOLD = 0.75  # cosine vs a link we previously flagged
BRAND_PAGE_SPOOF_MIN = 3       # brand name occurrences in page text before we call it a spoof claim
NEARDUP_THRESHOLD = 0.90       # MinHash similarity = same phishing kit
MAX_NETWORK_POINTS = 45        # cap for all network-derived signals combined
MAX_URLS_PER_MESSAGE = 5       # input validation: protect quota & event loop from spam


def _web_urls(text: str) -> list[str]:
    """Input validation layer: keep only web links and cap the count.

    - non-http(s) schemes (javascript:, data:, file:) are ignored —
      Telegram cannot render them, so they are not worth scoring;
    - more than MAX_URLS_PER_MESSAGE links are dropped (spam guard):
      each link costs network traces + possible VT quota.
    """
    kept: list[str] = []
    for url in extract_urls(text):
        if "://" in url:
            scheme = urlsplit(url).scheme.lower()
            if scheme not in ("http", "https"):
                logger.debug("ignored non-web url scheme %r", scheme)
                continue
        kept.append(url)
        if len(kept) >= MAX_URLS_PER_MESSAGE:
            logger.info("message had more than %d links; extras ignored",
                        MAX_URLS_PER_MESSAGE)
            break
    return kept


async def analyze_url(raw_url: str) -> dict:
    """Full async check of one URL -> merged verdict dict."""
    verdict = check_url(raw_url)
    score = verdict["score"]
    reasons = list(verdict["reasons"])
    detail: list[str] = []

    host = verdict["host"]
    if not host:
        # Unparseable — nothing else to run.
        return {**verdict, "detail": detail}

    normalized = raw_url if "://" in raw_url else f"http://{raw_url}"

    # Whitelist gate: an exact official brand domain can never be
    # pushed into "suspicious" by fuzzy signals (vector similarity,
    # past seen-links). This is what kept google.com safe from its own
    # http->www redirect noise.
    reg_domain = registered_domain(host)
    is_official_brand = reg_domain in PROTECTED_BRANDS

    # Network + DNS + RDAP concurrently; vector search is local CPU.
    net_task = asyncio.create_task(network.trace(normalized))
    dns_task = asyncio.create_task(resolve_host(host))
    age_task = asyncio.create_task(domain_age_days(host))

    net, ips, age_days = await asyncio.gather(net_task, dns_task, age_task,
                                              return_exceptions=True)
    if isinstance(net, Exception):
        net = None
    if isinstance(ips, Exception):
        ips = None
    if isinstance(age_days, Exception):
        age_days = None

    # --- Vector search over stored brand/phish embeddings -------------
    sim_hits = _safe_nearest(normalized)
    phish_sims = [s for s, kind, *_ in sim_hits if kind == "phish"]
    brand_sims = [s for s, kind, key, label in sim_hits if kind == "brand"]
    best_phish = max(phish_sims, default=0.0)
    best_brand_key = max(brand_sims, default=0.0)

    # Fuzzy n-gram similarity on short URLs is noisy (google.com sits
    # close to "login.google.verify-user.ml"), so phish-pattern points
    # are skipped entirely for official brand domains.
    if not is_official_brand:
        if best_phish >= PHISH_SIM_STRONG:
            score += 40
            reasons.append("Structurally near-identical to known phishing link patterns.")
            detail.append(f"vector search: best phishing-pattern similarity {best_phish:.2f}")
        elif best_phish >= PHISH_SIM_THRESHOLD:
            score += 20
            reasons.append("Resembles patterns seen in phishing links.")
            detail.append(f"vector search: phishing-pattern similarity {best_phish:.2f}")

    # --- DNS ----------------------------------------------------------
    if ips is None:
        score += 25
        reasons.append("The host name does not resolve in DNS at all — nothing is really there.")
    elif len(ips) <= 5:
        detail.append(f"DNS resolves to: {', '.join(ips[:3])}")

    # --- Domain registration age ---------------------------------------
    age_scored = score_domain_age(age_days)
    if age_scored:
        score += age_scored[0]
        reasons.append(age_scored[1])
    elif age_days:
        detail.append(f"Domain first registered {age_days}.")

    # --- Network-derived signals ---------------------------------------
    network_points = 0

    def add_network(points: int, reason: str):
        nonlocal network_points, score
        if network_points + points > MAX_NETWORK_POINTS:
            points = max(MAX_NETWORK_POINTS - network_points, 0)
        network_points += points
        score += points
        reasons.append(reason)

    if net is not None and net.get("error"):
        # A REAL certificate failure (handshake rejected) is strong
        # evidence; a plain-HTTP page is only worth the small padlock
        # signal — Google itself serves http://www.google.com.
        if net["tls_valid"] is False:
            add_network(30, "TLS certificate is invalid — connections are not secure.")
            detail.append(f"network: {net['error']}")
        else:
            add_network(15, "The server could not be reached (dead site or blocking bots).")
            detail.append(f"network: {net['error']}")
    elif net:
        chain = net.get("redirect_chain") or []
        final_url = net["final_url"]
        final_host = network._host(final_url)

        if chain:
            hops = " → ".join(network._host(u) for _, u in chain[-4:] + [(0, final_url)])
            detail.append(f"redirect chain ({len(chain)} hop(s)): {hops}")

        if net.get("cross_domain_redirect"):
            add_network(20, f"The link redirects to a different domain ({final_host}) — "
                            f"the visible address was not the real destination.")

            # Only a CROSS-DOMAIN redirect justifies re-scoring the
            # landing URL. google.com -> www.google.com is normal and
            # must not double-count signals.
            rescore = check_url(final_url)
            extra_points = min(rescore["score"], 30)
            if extra_points > 0:
                score += extra_points
                reasons.append(f"After following redirects it lands on '{final_host}', "
                               f"which shows its own warning signs.")
            detail.append(f"final destination: {final_host}")

        if len(chain) >= 4:
            add_network(10, f"Redirects through {len(chain)} hops before landing.")

        if net.get("tls_valid") is False:
            add_network(5, "The final page is served over plain HTTP — "
                           "anything you submit there is not encrypted.")

        if net["status"] and net["status"] >= 400:
            add_network(10, f"Server answered HTTP {net['status']} (error page).")

        # The landing page may impersonate even when the URL doesn't.
        page_text = net.get("page_text") or ""
        if page_text and not is_official_brand:
            spoof = _brand_page_spoof(page_text, final_host, best_brand_key)
            if spoof:
                score += 35
                reasons.append(spoof)

    # --- Match against links we've already flagged from Telegram -------
    # Gated by the brand whitelist so one mislabelled scan can never
    # poison the memory for official domains.
    seen_sim = 0.0
    if not is_official_brand:
        seen_sim = _best_seen_bad_similarity(normalized)
    if seen_sim >= SEEN_BAD_SIM_THRESHOLD:
        score += 20
        reasons.append("Closely resembles a link that was previously flagged "
                       "as suspicious or dangerous.")
        detail.append(f"similarity {seen_sim:.2f} to an earlier flagged link")

    # --- LSH near-duplicate page check (any fetched page) --------------
    if net and net.get("page_text"):
        dup_host = network._host(net["final_url"])
        dup = _safe_near_dup(dup_host, net["page_text"])
        if dup and dup[1] >= NEARDUP_THRESHOLD:
            other_host, similarity = dup
            score += 25
            reasons.append(f"Page content is near-identical to a page previously "
                           f"seen on {other_host}.")
            detail.append(f"LSH near-duplicate similarity {similarity:.2f} with {other_host}")

    # --- Flow 3: VirusTotal threat intelligence ------------------------
    # Quota-first: only spend a live API call when our own flows are
    # already suspicious; clean links answer from cache or not at all.
    # Official brand domains skip VT entirely — they never need it.
    if not is_official_brand:
        vt_target = net["final_url"] if isinstance(net, dict) and net.get("final_url") else normalized
        vt_stats = await threat_intel.lookup(
            vt_target, VIRUSTOTAL_API_KEY,
            live=(score > 0),
        )
        if vt_stats:
            vt_scored = threat_intel.score(vt_stats)
            if vt_scored:
                score += vt_scored[0]
                reasons.append(vt_scored[1])
                detail.append(f"VirusTotal: {vt_stats['malicious']} malicious / "
                              f"{vt_stats['suspicious']} suspicious of "
                              f"{vt_stats['total']} engines")

    # Final level from the merged score.
    level, emoji, label = _verdict_labels(score)

    # --- Remember this scan in the vector DB ---------------------------
    # Every link detected on Telegram is stored as kind='seen' with its
    # verdict level, so future lookalinks match against it. This must
    # happen AFTER the similarity query above, or a link would match
    # against itself.
    _remember(normalized, net, level)

    logger.info("verdict %s (%d) for %s", level, score, host)
    return {
        **verdict,
        "score": score,
        "level": level,
        "emoji": emoji,
        "label": label,
        "reasons": reasons,
        "detail": detail,
    }


def _best_seen_bad_similarity(text: str) -> float:
    """Highest cosine similarity to any link we previously flagged as
    suspicious/dangerous (kind='seen' rows carry their old verdict)."""
    best = 0.0
    for sim, kind, _key, label in _safe_nearest(text):
        if kind == "seen" and label in ("suspicious", "dangerous"):
            best = max(best, sim)
    return best


def _remember(normalized: str, net, level: str) -> None:
    """Store this link's embedding for future reference. The embedding
    text mixes URL syntax with a slice of page content so both a
    lookalike URL and a copied page can match it later."""
    try:
        final_url = network._host(normalized)
        if isinstance(net, dict) and net.get("final_url"):
            final_url = net["final_url"]
        page_slice = ""
        if isinstance(net, dict):
            page_slice = (net.get("page_text") or "")[:300]
        vectors.upsert_vector("seen", final_url.lower(),
                                   f"{normalized} {page_slice}".strip(), level)
    except Exception:                          # noqa: BLE001 - never fail a check on bookkeeping
        pass


def _safe_nearest(text: str):
    try:
        return vectors.nearest(text, k=4)
    except Exception:                          # noqa: BLE001 - DB trouble must not kill checks
        return []


def _safe_near_dup(host: str, page_text: str):
    try:
        sig = vectors.store_page_signature(host, page_text)
        return vectors.nearest_page(host, sig)
    except Exception:                          # noqa: BLE001
        return None


def _brand_page_spoof(page_text: str, final_host: str, best_brand_sim: float) -> str | None:
    """Page *claims* to be a bank/brand but sits on an unrelated domain —
    the semantic-impersonation case vector search alone can't prove."""
    from bot.linkchecker.lexical import PROTECTED_BRANDS
    low = page_text.lower()
    for domain, label in PROTECTED_BRANDS.items():
        brand = domain.split(".")[0]
        if low.count(brand) >= BRAND_PAGE_SPOOF_MIN and registered_domain(final_host) != domain:
            return (f"The page presents itself as {label}, but it lives on "
                    f"'{registered_domain(final_host)}' — not the official {label} domain.")
    return None


async def check_message_full(text: str) -> list[dict]:
    """Check every link in a message through the full pipeline."""
    urls = _web_urls(text)
    if not urls:
        return []
    return list(await asyncio.gather(*(analyze_url(u) for u in urls)))


def _risk_percent_and_label(score: int) -> tuple[int, str]:
    """Score capped to a 0-100 display percentage, bucketed independently of _verdict_labels."""
    pct = min(score, 100)
    if pct <= 30:
        return pct, "Low Risk"
    if pct <= 60:
        return pct, "Medium Risk"
    return pct, "High Risk"


_VERDICT_SENTENCES = {
    "dangerous": "This link is 🔴 *DANGEROUS* — avoid it.",
    "suspicious": "This link is 🟠 *SUSPICIOUS* — proceed with caution.",
    "safe": "This link is 🟢 *SAFE*.",
}

_RECOMMENDATIONS = {
    "dangerous": [
        "Do not open this link, log in, or enter any codes, passwords, or card details.",
        "If you already entered anything, change that password now and contact your bank or provider.",
        "Block and report the sender — this pattern matches known scam tactics.",
    ],
    "suspicious": [
        "Don't log in, pay, or enter personal details until you confirm this is legitimate.",
        "Go to the official site or app directly instead of clicking this link.",
        "If someone sent this to you, verify with them through a separate channel first.",
    ],
    "safe": [
        "No strong scam signals were found, but always double-check before entering sensitive info.",
        "Make sure the address matches the official site exactly before logging in.",
    ],
}


def format_verdict_full(v: dict, include_evidence: bool = True) -> str:
    """Full 5-section professional breakdown; include_evidence=False drops the Technical Evidence section."""
    pct, risk_label = _risk_percent_and_label(v["score"])
    verdict_sentence = _VERDICT_SENTENCES[v["level"]]
    recs = _RECOMMENDATIONS[v["level"]]

    lines = [
        "📡 *Angket Bot — Link Checker*",
        "",
        "🔗 *Scanned Link*",
        f"`{v['host']}`",
        "",
        "🛡️ *1. Verdict*",
        verdict_sentence,
        "",
        "📊 *2. Scam Risk Level*",
        f"{pct}% estimated scam risk — {risk_label}",
        "",
        "🔍 *3. Key Reasons*",
    ]
    lines += [f"  • {r}" for r in v["reasons"]]
    lines += [
        "",
        "💡 *4. What You Can Do*",
    ]
    lines += [f"  ✔ {r}" for r in recs]
    lines += [
        "",
        "ℹ️ *5. Heads Up*",
        "Bot can make mistakes. Please check carefully.",
    ]

    detail = v.get("detail") or []
    if include_evidence and detail:
        lines += ["", "🧾 *Technical Evidence*"]
        lines += [f"  · {d}" for d in detail]

    return "\n".join(lines)

