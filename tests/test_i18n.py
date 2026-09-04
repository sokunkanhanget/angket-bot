"""
tests/test_i18n.py
====================
Coverage for the new i18n keys added while porting panha's file-checker
result buttons (delete/ignore/view_on_virustotal action-button labels,
file_deleted/file_scan_ignored confirmations) - these replace panha's
separate locales.json/translator.py static-JSON system for that
feature, so this is the one place that content now lives. panha's
branch is scoped to the file checker specifically, so his other,
not-yet-functional main-menu items (Account Security/Passwords/Add to
Group/Donate) were intentionally left out of this merge.
"""

import pytest

from bot.i18n import BUTTONS, TEXT, key_for_label, label, t

NEW_BUTTON_KEYS = ["delete", "ignore", "view_on_virustotal"]
NEW_TEXT_KEYS = ["file_deleted", "file_scan_ignored"]


@pytest.mark.parametrize("key", NEW_BUTTON_KEYS)
@pytest.mark.parametrize("lang", ["en", "km"])
def test_new_button_labels_resolve_in_both_languages(key, lang):
    assert label(lang, key) != key
    assert label(lang, key) == BUTTONS[lang][key]


@pytest.mark.parametrize("key", NEW_TEXT_KEYS)
@pytest.mark.parametrize("lang", ["en", "km"])
def test_new_text_entries_resolve_in_both_languages(key, lang):
    assert t(lang, key) != key
    assert t(lang, key) == TEXT[lang][key]


@pytest.mark.parametrize("key", NEW_BUTTON_KEYS)
def test_key_for_label_maps_new_labels_back_to_their_key(key):
    for lang in ("en", "km"):
        assert key_for_label(BUTTONS[lang][key]) == key


def test_every_button_key_exists_in_both_languages():
    # Full key-parity, not just the hand-picked NEW_BUTTON_KEYS above -
    # a future PR adding an English button without its Khmer counterpart
    # (or vice versa) falls through silently today via t()/label()'s
    # `or ...[DEFAULT_LANG][key]` fallback, shipping English-leaking UI
    # to Khmer users with nothing catching it. This catches it.
    assert set(BUTTONS["en"].keys()) == set(BUTTONS["km"].keys())


def test_every_text_key_exists_in_both_languages():
    assert set(TEXT["en"].keys()) == set(TEXT["km"].keys())
