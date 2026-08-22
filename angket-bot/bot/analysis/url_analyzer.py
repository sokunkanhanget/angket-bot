"""
bot/analysis/url_analyzer.py
============================
The URL-checking brain for Angket Bot. Pure standard library — no
dependencies — so it can be tested on its own, just like text_analyzer.py.

Public functions the handler uses:
    check_message(text) -> list[dict]   # one verdict per URL found
    format_verdict(v)   -> str          # full breakdown for the reply
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit


# --- Reference data --------------------------------------------------
# Kept in this file for now to stay self-contained. If the team later
# wants one central place for lists, these can move to bot/config.py.

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

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "confirm", "wallet", "bonus", "free", "gift", "prize",
    "claim", "winner", "reward", "otp", "password", "unlock", "suspend",
    "recover",
}

MULTI_LEVEL_SUFFIXES = {
    "com.kh", "gov.kh", "edu.kh", "net.kh", "org.kh", "co.kh",
    "com.au", "co.uk", "org.uk", "gov.uk", "com.sg",
}

URL_REGEX = re.compile(
    r"(?:https?://)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,24}(?::\d{2,5})?(?:/[^\s<>()]*)?",
    re.IGNORECASE,
)

LEVEL_META = {
    "safe": ("🟢", "Looks OK"),
    "suspicious": ("🟠", "Suspicious"),
    "dangerous": ("🔴", "Dangerous"),
}


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


# --- Checks ----------------------------------------------------------

def _brand_check(host: str, reg: str):
    for brand_domain, label in PROTECTED_BRANDS.items():
        if reg == brand_domain:
            return None
        dist = levenshtein(reg, brand_domain)
        if 0 < dist <= 2 and abs(len(reg) - len(brand_domain)) <= 3:
            return (45, f"Domain '{reg}' closely imitates {label} ({brand_domain}) — likely a fake.")
        brand_name = brand_domain.split(".")[0]
        if len(brand_name) >= 4 and brand_name in host and reg != brand_domain:
            return (40, f"Mentions '{brand_name}' but the real domain is '{reg}', not {label}'s official site.")
    return None


def _classify(score: int) -> str:
    if score >= 60:
        return "dangerous"
    if score >= 25:
        return "suspicious"
    return "safe"


def check_url(raw_url: str) -> dict:
    """Score one URL and return a verdict dict."""
    normalized, host, parts = _normalize(raw_url)
    reasons: list[str] = []
    score = 0

    if not host:
        emoji, label = LEVEL_META["safe"]
        return {"raw": raw_url, "host": "", "score": 0, "level": "safe",
                "reasons": ["Could not parse this as a link."],
                "emoji": emoji, "label": label}

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

    hits = sorted(w for w in SUSPICIOUS_KEYWORDS if w in host or w in path_query)
    if hits:
        score += min(len(hits) * 10, 30)
        reasons.append(f"Contains scam-typical words: {', '.join(hits[:4])}.")

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

    level = _classify(score)
    if level == "safe" and not reasons:
        reasons.append("No common scam signals detected. Still, stay alert.")

    emoji, label = LEVEL_META[level]
    return {"raw": raw_url, "host": host, "score": score, "level": level,
            "reasons": reasons, "emoji": emoji, "label": label}


def check_message(text: str) -> list[dict]:
    """Check every link in a message. Empty list if no links found."""
    return [check_url(u) for u in extract_urls(text)]


def format_verdict(v: dict) -> str:
    """Full breakdown for one URL, ready to send as a Telegram reply."""
    lines = [
        f"{v['emoji']} {v['label']}  (risk score: {v['score']})",
        f"Link: `{v['host']}`",
        "",
    ]
    lines += [f"• {r}" for r in v["reasons"]]
    if v["level"] != "safe":
        lines += ["", "⚠️ Do not log in, pay, or enter codes on this link."]
    return "\n".join(lines)