"""
tests/test_button.py
======================
Coverage for bot/response/buttons.py - the BUTTONS dict (main-menu
keyboard labels) and key_for_label()'s reverse lookup. Reply-content
coverage (TEXT) lives in tests/test_translate.py, mirroring
bot/response/ vs. bot/response/'s split.
"""

from bot.response.buttons import BUTTONS, key_for_label


def test_every_button_key_exists_in_both_languages():
    # Full key-parity - a future PR adding an English button without its
    # Khmer counterpart (or vice versa) falls through silently today via
    # label()'s `or ...[DEFAULT_LANG][key]` fallback, shipping
    # English-leaking UI to Khmer users with nothing catching it. This
    # catches it.
    assert set(BUTTONS["en"].keys()) == set(BUTTONS["km"].keys())


def test_key_for_label_resolves_every_button_in_both_languages():
    for lang in ("en", "km"):
        for key, text in BUTTONS[lang].items():
            assert key_for_label(text) == key
