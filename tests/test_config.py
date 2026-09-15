"""
tests/test_config.py
=====================
DISPLAY_TIMEZONE_OFFSET_HOURS's env parsing - the one config value in
this module that runs int() on a user-supplied string at IMPORT time.

Every other optional env value here degrades gracefully on bad input
(VIRUSTOTAL_API_KEY/GEMINI_API_KEY being unset, ADMIN_CHAT_ID being
None) - this one used to crash the whole bot at startup on a malformed
.env line instead of falling back like its siblings.

Reloads the real module under a monkeypatched environment rather than
re-implementing the parsing logic separately, so this tests the actual
import-time code path, not a copy of it. importlib.reload runs the
module body again in place, so no separate module object is left
behind to clean up - reloading once more at the end (env restored by
monkeypatch's own teardown) puts the shared module back the way every
other test expects to find it.
"""

import importlib

from bot.config import config as config_module


def _reload_with_env(monkeypatch, value: str | None):
    if value is None:
        monkeypatch.delenv("DISPLAY_TIMEZONE_OFFSET_HOURS", raising=False)
    else:
        monkeypatch.setenv("DISPLAY_TIMEZONE_OFFSET_HOURS", value)
    importlib.reload(config_module)


def test_missing_env_value_defaults_to_seven(monkeypatch):
    _reload_with_env(monkeypatch, None)
    assert config_module.DISPLAY_TIMEZONE_OFFSET_HOURS == 7


def test_valid_override_is_used(monkeypatch):
    _reload_with_env(monkeypatch, "9")
    assert config_module.DISPLAY_TIMEZONE_OFFSET_HOURS == 9


def test_negative_override_is_used(monkeypatch):
    # A real, valid use case (a deployment west of UTC) - negative
    # values must not be mistaken for "invalid" by the parser.
    _reload_with_env(monkeypatch, "-5")
    assert config_module.DISPLAY_TIMEZONE_OFFSET_HOURS == -5


def test_malformed_value_falls_back_to_seven_instead_of_crashing(monkeypatch, caplog):
    # The real regression: int("not-a-number") used to raise ValueError
    # straight out of the module body, crashing the whole bot at import
    # time on nothing more than a typo'd .env line.
    _reload_with_env(monkeypatch, "not-a-number")

    assert config_module.DISPLAY_TIMEZONE_OFFSET_HOURS == 7
    assert any("not a valid integer" in record.message for record in caplog.records)


def test_empty_string_value_falls_back_to_seven(monkeypatch):
    # os.getenv's own default only covers the key being UNSET - a real
    # ".env" line like "DISPLAY_TIMEZONE_OFFSET_HOURS=" sets it to "",
    # which int() also rejects.
    _reload_with_env(monkeypatch, "")
    assert config_module.DISPLAY_TIMEZONE_OFFSET_HOURS == 7


def test_whitespace_only_value_falls_back_to_seven(monkeypatch):
    _reload_with_env(monkeypatch, "   ")
    assert config_module.DISPLAY_TIMEZONE_OFFSET_HOURS == 7


def teardown_module(module):
    # Leave the shared config module in its normal (env-unset -> 7)
    # state for every test file that imports it after this one.
    import os
    os.environ.pop("DISPLAY_TIMEZONE_OFFSET_HOURS", None)
    importlib.reload(config_module)
