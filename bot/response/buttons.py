"""
bot/response/buttons.py
=============================
Main-menu button labels (BUTTONS) - what a keyboard button SAYS, as
opposed to bot/response/translate/'s TEXT - what a reply/menu page
SAYS. Split out of the old bot/i18n.py so the two concerns (buttons vs.
reply content) live in separate modules; t()/label()/key_for_label()
live here too since they're the lookup functions button-driven handlers
actually call (t() reaches into translate.py's TEXT for the reply-content
half of the same lookup pattern).
"""

from bot.response.translate import DEFAULT_LANG, TEXT

BUTTONS = {
    "en": {
        "menu": "MENU",
        "switch_language": "🌐 Switch Language",
        "lang_en": "English",
        "lang_km": "ខ្មែរ",
        "back": "↩️ Back",
        "how_to_use": "📖 How to Use",
        "usage": "📈 Usage",
        "policy": "📜 Policy",
        "help": "❓ Help",
        "subscription": "⭐ Subscription",
    },
    "km": {
        "menu": "ម៉ឺនុយ",
        "switch_language": "🌐 ផ្លាស់ប្តូរភាសា",
        "lang_en": "English",
        "lang_km": "ខ្មែរ",
        "back": "↩️ ត្រឡប់ក្រោយ",
        "how_to_use": "📖 របៀបប្រើប្រាស់",
        "usage": "📈 ការប្រើប្រាស់",
        "policy": "📜 គោលការណ៍",
        "help": "❓ ជំនួយ",
        "subscription": "⭐ ការជាវ",
    },
}


def _normalize_lang(lang: str | None) -> str:
    return lang if lang in BUTTONS else DEFAULT_LANG


def t(lang: str | None, key: str) -> str:
    locale = _normalize_lang(lang)
    return TEXT.get(locale, {}).get(key) or TEXT.get(DEFAULT_LANG, {}).get(key) or key


def label(lang: str | None, key: str) -> str:
    locale = _normalize_lang(lang)
    return BUTTONS.get(locale, {}).get(key) or BUTTONS.get(DEFAULT_LANG, {}).get(key) or key


def key_for_label(text: str) -> str | None:
    normalized = (text or "").strip()
    if not normalized:
        return None

    for lang, labels in BUTTONS.items():
        for key, label_text in labels.items():
            if normalized == label_text:
                return key
    return None
