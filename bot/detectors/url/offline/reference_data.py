"""
bot/detectors/url/offline/reference_data.py
==============================================
Pure reference-data lists used by lexical.py's checks: known official
brand domains, abused free TLDs, URL-shortener services, scam-typical
URL keywords, and multi-level country-code suffixes. Split out of
lexical.py itself so that file holds only detection logic - these lists
grow/change independently of the scoring code that reads them, and
splitting them out keeps lexical.py focused on "how do we score a URL"
rather than "what do we know about the world."

Re-exported through lexical.py (which imports from here) so every
existing caller (`from bot.detectors.url.offline.lexical import
PROTECTED_BRANDS`, etc., used across pipeline.py/vectors.py/tests) keeps
working unchanged - this is a pure file-organization change, not an API
change.
"""

from __future__ import annotations

PROTECTED_BRANDS = {
    "ababank.com": "ABA Bank",
    "acledabank.com.kh": "ACLEDA Bank",
    "wingmoney.com": "Wing",
    "truemoney.com.kh": "TrueMoney",
    "pipay.com": "Pi Pay",
    "cellcard.com.kh": "Cellcard",
    "smart.com.kh": "Smart Axiata",
    # Cambodian banks/telecoms added later - domains verified live via
    # web search (2026-09-05), not guessed, since a wrong entry here
    # would be worse than no entry at all (it feeds both typosquat
    # scoring and the official-brand trust whitelist).
    "metfone.com.kh": "Metfone",  # Cambodia's third major telecom - was a real gap, Cellcard/Smart were already covered
    "canadiabank.com.kh": "Canadia Bank",
    "sathapana.com.kh": "Sathapana Bank",
    "vattanacbank.com": "Vattanac Bank",
    "princebank.com.kh": "Prince Bank",
    "phillipbank.com.kh": "Phillip Bank",
    "kbprasacbank.com.kh": "KB PRASAC Bank",  # merged from PRASAC Microfinance + Kookmin Bank Cambodia, 2023
    "nbc.gov.kh": "National Bank of Cambodia / Bakong",  # bakong.nbc.gov.kh reduces to this via the existing gov.kh MULTI_LEVEL_SUFFIXES entry
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "telegram.org": "Telegram",
    "google.com": "Google",
    "gmail.com": "Gmail",
    "microsoft.com": "Microsoft",
    "outlook.com": "Outlook",
    "apple.com": "Apple",
    "paypal.com": "PayPal",
    "binance.com": "Binance",
    "whatsapp.com": "WhatsApp",
    "netflix.com": "Netflix",
    "amazon.com": "Amazon",
    "tiktok.com": "TikTok",
    "linkedin.com": "LinkedIn",
    "dropbox.com": "Dropbox",
    "x.com": "X (Twitter)",  # rebranded 2023-2024; twitter.com still redirects here, kept below too
    "twitter.com": "Twitter",
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

MULTI_LEVEL_SUFFIXES = {
    "com.kh", "gov.kh", "edu.kh", "net.kh", "org.kh", "co.kh",
    "com.au", "co.uk", "org.uk", "gov.uk", "com.sg",
}
