DEFAULT_LANG = "en"

BUTTONS = {
    "en": {
        "menu": "MENU",
        "switch_language": "🌐 Switch Language",
        "lang_en": "English",
        "lang_km": "ខ្មែរ",
        "back": "↩️ Back",
        "how_to_use": "📖 How to Use",
        "safety_tips": "🛡️ Safety Tips",
        "live_scan": "🔎 Live Message Scan",
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
        "safety_tips": "🛡️ គន្លឹះសុវត្ថិភាព",
        "live_scan": "🔎 ការពិនិត្យដោយស្វ័យប្រវត្តិ",
        "policy": "📜 គោលការណ៍",
        "help": "❓ ជំនួយ",
        "subscription": "⭐ ការជាវ",
    },
}

TEXT = {
    "en": {
        "switch_language": "🌐 <b>Switch Language</b>",
        "language_set": "Language set to English.",
    },
    "km": {
        "switch_language": "🌐 <b>ផ្លាស់ប្តូរភាសា</b>",
        "language_set": "ភាសាត្រូវបានកំណត់ជា ខ្មែរ។",
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
