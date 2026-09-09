"""
tests/test_translate.py
=========================
Coverage for bot/translate/translate.py - the TEXT dict (reply content:
verdicts, reasons headers, disclaimers, menu pages, etc.) and its en/km
key parity. Button-label coverage (BUTTONS, key_for_label) lives in
tests/test_button.py, mirroring bot/translate/ vs. bot/button/'s split.
"""

import pytest

from bot.translate.translate import TEXT
from bot.button.start_button import t

NEW_TEXT_KEYS = ["type_label"]


@pytest.mark.parametrize("key", NEW_TEXT_KEYS)
@pytest.mark.parametrize("lang", ["en", "km"])
def test_new_text_entries_resolve_in_both_languages(key, lang):
    assert t(lang, key) != key
    assert t(lang, key) == TEXT[lang][key]


def test_every_text_key_exists_in_both_languages():
    # Full key-parity - a future PR adding an English reply string without
    # its Khmer counterpart (or vice versa) falls through silently today
    # via t()'s `or ...[DEFAULT_LANG][key]` fallback, shipping
    # English-leaking replies to Khmer users with nothing catching it.
    # This catches it.
    assert set(TEXT["en"].keys()) == set(TEXT["km"].keys())
