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
    # Facebook/Messenger's own real short-link domains, same pattern as
    # Telegram above - confirmed live: fb.com and fb.me both genuinely
    # redirect to www.facebook.com (real Facebook infra, not a scam
    # redirect), and m.me is Messenger's real message-link domain used
    # on every Facebook Page's "Send Message" button. Before these
    # entries existed, fb.com scored 65/dangerous as "a fake of X
    # (Twitter)" (x.com) and fb.me/m.me scored the same against Telegram
    # (t.me) - the short-domain-typosquat false positive _brand_check's
    # MIN_TYPOSQUAT_DOMAIN_LENGTH guard fixes generally; these entries
    # are still needed so is_official_brand recognizes them as
    # Facebook/Messenger's own domains (skips phish-vector scoring,
    # etc.) and so pipeline.py's KNOWN_FIRST_PARTY_REDIRECTS entry for
    # them actually has a real brand behind it.
    "fb.com": "Facebook",
    "fb.me": "Facebook",
    "messenger.com": "Messenger",
    "m.me": "Messenger",
    # Discord's own real invite-link domain - confirmed live: discord.gg
    # genuinely redirects to discord.com (real Discord infra). Discord
    # itself wasn't previously a protected brand at all, despite being a
    # very common real impersonation target (fake Nitro/giveaway scams).
    "discord.com": "Discord",
    "discord.gg": "Discord",
    # Reddit's own real post-shortlink domain - confirmed live: redd.it
    # genuinely redirects to www.reddit.com. Reddit wasn't previously a
    # protected brand at all either.
    "reddit.com": "Reddit",
    "redd.it": "Reddit",
    "instagram.com": "Instagram",
    "telegram.org": "Telegram",
    # Telegram itself operates two other fully real, legitimate domains
    # for channel/bot/invite links - t.me is what nearly every real
    # Telegram link users actually share looks like, telegram.me is the
    # original (pre-t.me) domain and still directly serves the same
    # real content (confirmed live: telegram.me/telegram returns
    # Telegram's own channel-preview page, "9,614,677 subscribers",
    # nginx, no redirect needed - it's genuinely Telegram's own infra,
    # not a redirect through it). Real, confirmed false positive: before
    # this entry existed, telegram.me scored 80/dangerous, "impersonating"
    # telegram.org - see _brand_check's top-of-function short-circuit,
    # which is what actually makes a brand's OWN other domain here safe
    # against every OTHER brand entry, not just its own.
    "telegram.me": "Telegram",
    "t.me": "Telegram",
    "google.com": "Google",
    # Google's own official shortlink domain - confirmed live: g.co
    # genuinely redirects to real Google-owned infrastructure, but NOT
    # to one fixed destination - g.co/gemini -> ai.google.dev,
    # g.co/photos -> www.google.com, g.co/ai -> ai.google (Google owns
    # the .google gTLD too). See pipeline.py's KNOWN_FIRST_PARTY_REDIRECTS,
    # which supports multiple allowed destinations per source
    # specifically because of this - g.co's redirect scoring IS covered
    # (all 3 confirmed destinations listed there), this entry additionally
    # gives it brand recognition (typosquat/buried-name immunity,
    # phish-vector skip).
    "g.co": "Google",
    "youtube.com": "YouTube",
    # youtu.be is YouTube's own real, extremely common share-link domain
    # - confirmed live: redirects to www.youtube.com.
    "youtu.be": "YouTube",
    "gmail.com": "Gmail",
    "microsoft.com": "Microsoft",
    "outlook.com": "Outlook",
    "apple.com": "Apple",
    "paypal.com": "PayPal",
    "binance.com": "Binance",
    "whatsapp.com": "WhatsApp",
    # WhatsApp's own official click-to-chat domain - confirmed live:
    # wa.me genuinely redirects to api.whatsapp.com.
    "wa.me": "WhatsApp",
    "netflix.com": "Netflix",
    "amazon.com": "Amazon",
    # Amazon's own official link-shortener domain - confirmed live:
    # amzn.to genuinely redirects to www.amazon.com.
    "amzn.to": "Amazon",
    "tiktok.com": "TikTok",
    "linkedin.com": "LinkedIn",
    # LinkedIn's own official shortener domain. Recognized as a real
    # LinkedIn domain (brand immunity) but NOT added to
    # KNOWN_FIRST_PARTY_REDIRECTS - unlike amzn.to/wa.me/youtu.be above,
    # a real, valid lnkd.in redirect was never actually observed live
    # (the test path used didn't resolve to one), so its destination
    # isn't confirmed to the same standard of evidence the others are.
    "lnkd.in": "LinkedIn",
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
