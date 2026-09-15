"""
tests/test_translate.py
=========================
Coverage for bot/response/translate/ - the TEXT dict (reply content:
verdicts, reasons headers, disclaimers, menu pages, etc.) and its en/km
key parity. Button-label coverage (BUTTONS, key_for_label) lives in
tests/test_button.py, mirroring bot/response/ vs. bot/response/'s split.
"""

import pytest

from bot.response.translate import TEXT
from bot.response.buttons import t

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


# --- Keys used by the Gemini-bypassing verdict paths -------------------
# Gemini writes its own key_reasons/recommendations directly in the
# user's language, so those never needed table entries. Every path that
# BYPASSES Gemini was therefore emitting raw English into an otherwise
# fully-translated Khmer reply: the offline fallback, the dead-link and
# trusted-brand short-circuits, the evidence-reconciliation overrides,
# and the group-chat link reply.

GEMINI_BYPASS_KEYS = [
    "reason_keyword_match",
    "reason_scam_script",
    "reason_link_flagged",
    "reason_file_malicious",
    "reason_override_file",
    "reason_override_link",
    "reason_override_scam_script",
    "reason_dead_link",
    "reason_trusted_brand",
    "rec_scam_no_interaction",
    "rec_scam_block_report",
    "rec_uncertain_hold_off",
    "rec_uncertain_verify_sender",
    "rec_safe_stay_cautious",
    "rec_dead_link_no_credentials",
    "rec_dead_link_check_sender",
    "rec_link_dangerous_no_entry",
    "rec_link_dangerous_already_entered",
    "rec_link_dangerous_block",
    "rec_link_suspicious_hold_off",
    "rec_link_suspicious_go_direct",
    "rec_link_suspicious_verify_sender",
    "rec_link_safe_double_check",
    "rec_link_safe_match_address",
    # File scanning never involves Gemini at all, so every reason and
    # recommendation it shows was fixed English - the same bug class,
    # just with no live path that was ever translated.
    "filename_warning_double_extension_executable",
    "filename_warning_double_extension_archive",
    "filename_warning_lone_executable",
    "reason_file_engines_flag",
    "reason_file_clean_but_name_suspect",
    "reason_file_no_engine_flags",
    "reason_file_name_only",
    "reason_file_never_seen",
    "reason_file_no_name_flags",
    "rec_file_dangerous_do_not_open",
    "rec_file_dangerous_already_opened",
    "rec_file_dangerous_delete_block",
    "rec_file_suspicious_verify_sender",
    "rec_file_suspicious_scan_first",
    "rec_file_safe_no_signals",
    "rec_file_safe_trusted_senders",
    "rec_file_uncertain_caution",
    "rec_file_uncertain_verify_sender",
]


@pytest.mark.parametrize("key", GEMINI_BYPASS_KEYS)
@pytest.mark.parametrize("lang", ["en", "km"])
def test_gemini_bypass_keys_resolve_in_both_languages(key, lang):
    assert t(lang, key) != key, f"{key} missing from {lang}"
    assert t(lang, key).strip()


@pytest.mark.parametrize("key", GEMINI_BYPASS_KEYS)
def test_gemini_bypass_keys_are_really_translated_into_khmer(key):
    # t() silently falls back to English for a missing key, so key parity
    # alone cannot tell a real Khmer string from an English one sitting
    # in the Khmer table. Requiring actual Khmer-script characters can.
    khmer = t("km", key)
    assert any(0x1780 <= ord(ch) <= 0x17FF for ch in khmer), (
        f"{key}'s Khmer entry contains no Khmer script: {khmer!r}"
    )
    assert khmer != t("en", key)


@pytest.mark.parametrize("key", GEMINI_BYPASS_KEYS)
def test_placeholders_match_between_languages(key):
    # These strings are .format()ted by the caller. A placeholder present
    # in English but missing (or misspelled) in Khmer would either drop
    # real evidence from the reply or raise KeyError mid-reply for a
    # Khmer user only - a failure no English-language test could see.
    import string

    def placeholders(text):
        return {name for _lit, name, _spec, _conv in string.Formatter().parse(text) if name}

    assert placeholders(t("en", key)) == placeholders(t("km", key)), key


def test_no_stray_similarity_score_is_exposed_in_any_language():
    # The 9th session's decision: internal detection-method and
    # confidence details never reach the user. The scam-script override
    # reason used to append "(0.54 similarity)".
    for lang in ("en", "km"):
        assert "similarity" not in t(lang, "reason_override_scam_script").lower()
        assert "similarity" not in t(lang, "reason_scam_script").lower()
