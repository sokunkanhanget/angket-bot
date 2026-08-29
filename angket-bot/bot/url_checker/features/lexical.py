"""
bot/url_checker/features/lexical.py
=====================================
The URL-checking brain for Angket Bot. Pure standard library — no
dependencies — so it can be tested on its own, just like text_analyzer.py.

Public functions the handler uses:
    check_message(text) -> list[dict]   # one verdict per URL found
    format_verdict(v)   -> str          # full breakdown for the reply
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlsplit


# --- Reference data --------------------------------------------------

PROTECTED_BRANDS = {
    "ababank.com": "ABA Bank",
    "acledabank.com.kh": "ACLEDA Bank",
    "wingmoney.com": "Wing",
    "truemoney.com.kh": "TrueMoney",
    "pipay.com": "Pi Pay",
    "cellcard.com.kh": "Cellcard",
    "smart.com.kh": "Smart Axiata",
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "telegram.org": "Telegram",
    "google.com": "Google",
    "gmail.com": "Gmail",
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "paypal.com": "PayPal",
    "binance.com": "Binance",
    "whatsapp.com": "WhatsApp",
    "netflix.com": "Netflix",
}

ABUSED_TLDS = {"tk", "ml", "ga", "cf", "gq"}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy",
    "shorte.st", "adf.ly", "bc.vc",
}

SUSPICIOUS_URL_WORDS = {
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "confirm", "wallet", "bonus", "free", "gift", "prize",
    "claim", "winner", "reward", "otp", "password", "unlock", "suspend",
    "recover",
}

ENTROPY_MIN_LENGTH = 8    # shorter labels are too small to measure meaningfully
ENTROPY_MIN_DIGITS = 2    # real brand/dictionary names almost never mix digits mid-name
ENTROPY_THRESHOLD = 3.0   # bits/char - calibrated against synthetic random labels; see domain_entropy

MULTI_LEVEL_SUFFIXES = {
    "com.kh", "gov.kh", "edu.kh", "net.kh", "org.kh", "co.kh",
    "com.au", "co.uk", "org.uk", "gov.uk", "com.sg",
}

URL_REGEX = re.compile(
    r"(?:https?://)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,24}(?::\d{2,5})?(?:/[^\s<>()]*)?",
    re.IGNORECASE,
)


# --- Helpers ---------------------------------------------------------

def levenshtein(a: str, b: str) -> int:
    """Edit distance — used to catch typosquats like ababamk.com."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[len(b)]


def registered_domain(host: str) -> str:
    """Reduce a host to its owning domain, handling .com.kh style suffixes."""
    labels = host.split(".")
    if len(labels) < 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _deleet(s: str) -> str:
    """Turn leetspeak back to letters so g00gle -> google before comparing."""
    return s.translate(LEET_MAP)


def extract_urls(text: str) -> list[str]:
    """Find every URL in a message, de-duplicated."""
    seen = set()
    out = []
    for match in URL_REGEX.finditer(text or ""):
        url = match.group(0).rstrip(".,);]!?'\"")
        key = url.lower()
        if key not in seen:
            seen.add(key)
            out.append(url)
    return out


def _normalize(url: str):
    normalized = url if "://" in url else f"http://{url}"
    parts = urlsplit(normalized)
    host = (parts.hostname or "").lower()
    return normalized, host, parts


def domain_entropy(label: str) -> float:
    """Shannon entropy in bits/char - raw character diversity.

    Deliberately NOT used alone (see check_url): at domain-name lengths
    (8-16 chars) it's noisy on its own - a real dictionary word like
    "subscription" (entropy ~3.25) can score HIGHER than a genuinely
    random 8-char string like "pbhsahxt" (~2.75), since Shannon entropy
    measures character diversity, not "does this look like language".
    check_url() gates this on digit-mixing first: real brand/dictionary
    names essentially never intersperse digits mid-name, which is a far
    more precise auto-generated-domain signal than entropy alone.
    """
    if not label:
        return 0.0
    length = len(label)
    counts = Counter(label)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def check_anchor_mismatch(display_text: str, actual_url: str) -> tuple[int, str] | None:
    """Flags a link whose DISPLAYED text is itself URL/domain-shaped but
    points somewhere else - e.g. a message shows "https://ababank.com"
    while the real destination (a Telegram MessageEntity.TEXT_LINK's
    url, which can differ freely from what's shown) is a phishing
    domain. Ordinary descriptive link text ("click here", "read more")
    has nothing URL-shaped to compare, so it's never flagged - that's
    completely normal hyperlink usage, not a scam signal on its own.
    """
    display_urls = extract_urls(display_text)
    if not display_urls:
        return None

    _, display_host, _ = _normalize(display_urls[0])
    _, actual_host, _ = _normalize(actual_url)
    if not display_host or not actual_host:
        return None

    if registered_domain(display_host) != registered_domain(actual_host):
        return (55, f"Link text shows '{display_host}' but actually goes to "
                    f"'{actual_host}' — the displayed address is not the real destination.")
    return None


def _verdict_labels(score: int):
    """Turn a score into (level, emoji, label)."""
    if score >= 60:
        return "dangerous", "🔴", "Dangerous"
    if score >= 25:
        return "suspicious", "🟠", "Suspicious"
    return "safe", "🟢", "Looks OK"


# --- Checks ----------------------------------------------------------

def _brand_check(host: str, reg: str):
    reg_leet = _deleet(reg)
    host_leet = _deleet(host)
    for brand_domain, label in PROTECTED_BRANDS.items():
        brand_name = brand_domain.split(".")[0]

        # Real, untouched domain match -> legitimate, stop.
        if reg == brand_domain:
            return None

        # Matches the real brand ONLY after removing leetspeak (faceb00k -> facebook)
        # -> that's a deliberate disguise, strongest signal.
        if reg_leet == brand_domain:
            return (50, f"Domain '{reg}' is a disguised copy of {label} ({brand_domain}).")

        # Close-but-not-equal (typosquat), on raw or de-leeted domain.
        for r in (reg, reg_leet):
            dist = levenshtein(r, brand_domain)
            if 0 < dist <= 2 and abs(len(r) - len(brand_domain)) <= 3:
                return (45, f"Domain looks like a fake of {label} ({brand_domain}).")

        # Brand name buried in the host, but the domain isn't the official one.
        for h in (host, host_leet):
            if len(brand_name) >= 4 and brand_name in h and reg != brand_domain:
                return (45, f"Mentions '{brand_name}' but the real domain is '{reg}', not {label}'s official site.")
    return None


def check_url(raw_url: str) -> dict:
    """Score one URL and return a verdict dict."""
    normalized, host, parts = _normalize(raw_url)
    reasons: list[str] = []
    score = 0

    if not host:
        return {"raw": raw_url, "host": "", "score": 0, "level": "safe",
                "reasons": ["Could not parse this as a link."],
                "emoji": "🟢", "label": "Looks OK"}

    reg = registered_domain(host)
    path_query = (parts.path + "?" + parts.query).lower()
    tld = host.rsplit(".", 1)[-1] if "." in host else ""

    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        score += 45
        reasons.append("Uses a raw IP address instead of a domain name.")

    if parts.username or parts.password:
        score += 40
        reasons.append("Contains '@' in the address — a trick to hide the real destination.")

    if "xn--" in host:
        score += 30
        reasons.append("Uses punycode (xn--) to imitate a real domain.")

    if host in URL_SHORTENERS or reg in URL_SHORTENERS:
        score += 25
        reasons.append("Shortened link — the real destination is hidden until you click.")

    if tld in ABUSED_TLDS:
        score += 25
        reasons.append(f"Domain ends in .{tld}, a free TLD heavily used for scams.")

    brand = _brand_check(host, reg)
    if brand:
        score += brand[0]
        reasons.append(brand[1])

    hits = sorted(w for w in SUSPICIOUS_URL_WORDS if w in host or w in path_query)
    if hits:
        score += min(len(hits) * 10, 30)
        reasons.append(f"Contains scam-typical words: {', '.join(hits[:4])}.")

    # Skip on an already-flagged brand disguise/typosquat - a known-bad
    # domain doesn't need a second, redundant "looks random" reason.
    # Gated on digit-mixing before entropy: real brand/dictionary names
    # essentially never intersperse digits mid-name, so this alone
    # already excludes real words that happen to score high on raw
    # character-diversity entropy (see domain_entropy's docstring).
    core_label = reg.split(".")[0] if reg else ""
    digit_count = sum(1 for c in core_label if c.isdigit())
    if not brand and len(core_label) >= ENTROPY_MIN_LENGTH and digit_count >= ENTROPY_MIN_DIGITS:
        entropy = domain_entropy(core_label)
        if entropy >= ENTROPY_THRESHOLD:
            score += 15
            reasons.append(f"Domain name '{core_label}' looks randomly generated "
                            f"(mixed digits/letters, high character entropy) — common in auto-generated scam domains.")

    labels_before = []
    if reg and host.endswith(reg):
        labels_before = [l for l in host[: -len(reg)].strip(".").split(".") if l]
    if len(labels_before) >= 3:
        score += 15
        reasons.append("Has an unusually deep subdomain chain, which can disguise the real site.")

    if host.count("-") >= 3:
        score += 10
        reasons.append("Host name is stuffed with hyphens, common in fake sites.")

    if len(normalized) > 90:
        score += 5
        reasons.append("The link is unusually long.")

    if parts.scheme != "https":
        score += 5
        reasons.append("Not served over HTTPS (no padlock).")

    level, emoji, label = _verdict_labels(score)
    if level == "safe" and not reasons:
        reasons.append("No common scam signals detected. Still, stay alert.")

    return {"raw": raw_url, "host": host, "score": score, "level": level,
            "reasons": reasons, "emoji": emoji, "label": label}


def check_message(text: str) -> list[dict]:
    """Check every link in a message. Empty list if no links found."""
    return [check_url(u) for u in extract_urls(text)]


def format_verdict(v: dict) -> str:
    """Lexical-only preview — see pipeline.format_verdict_full for the actual reply template."""
    lines = [
        f"{v['emoji']} {v['label']}  (risk score: {v['score']})",
        f"Link: `{v['host']}`",
        "",
    ]
    lines += [f"• {r}" for r in v["reasons"]]
    if v["level"] != "safe":
        lines += ["", "⚠️ Do not log in, pay, or enter codes on this link."]
    return "\n".join(lines)
