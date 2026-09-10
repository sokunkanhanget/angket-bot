"""
bot/response/translate/__init__.py
=====================================
All translatable CONTENT text - verdict labels, risk levels, key-reasons/
what-to-do headers, disclaimers, menu pages (how-to-use/policy/etc.),
and every other fixed string a reply actually shows to a user. Split
one file per language (en.py, km.py, ...) so adding or editing a
language never touches another one's text - this file just combines
them into the same {"en": {...}, "km": {...}} shape every caller
already imports (`from bot.response.translate import DEFAULT_LANG,
TEXT`), so no call site needed to change for this split.

Content translation lives separately from bot/response/buttons.py's
menu BUTTON labels (a different concern: what a keyboard button says
vs. what a reply says).

Dynamic per-call text (Gemini's own key_reasons/recommendations) is NOT
here - Gemini is asked to respond directly in the target language (see
context_engine.py's lang param); this only covers the FIXED strings
around that dynamic text, translated once instead of round-tripping
through the model for a handful of fixed words every call.

Adding a new language: create a new <lang>.py here with its own TEXT
dict (same keys as en.py - anything missing falls back to English,
see bot/response/buttons.py's t()), then add it below.
"""

from . import en, km

DEFAULT_LANG = "en"

TEXT = {
    "en": en.TEXT,
    "km": km.TEXT,
}
