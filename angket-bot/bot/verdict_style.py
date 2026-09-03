"""
bot/verdict_style.py
======================
Shared verdict/risk display styling - used by both the private-DM reply
(text_handler.py) and the business-owner-DM notification
(url_checker/message/handler.py), so the two surfaces can never silently
diverge on what counts as "High Risk" or how a verdict is labelled.

Both verdict_style() and risk_style() take a `lang` - the labels are
FIXED text (not something Gemini generates per call), so they're
translated once via i18n.py instead of round-tripping through the model
for a handful of words every single call. Group chat (bot/route.py's
TEXT_FILTER path) deliberately keeps calling these with lang="en" -
see text_handler.py's format_analysis_response - group replies are out
of scope for translation for now, unlike private DM/business chat.
"""

from __future__ import annotations

from bot.i18n import DEFAULT_LANG, t

_VERDICT_ICONS = {
    "Scam": "⚠️",
    "Not a Scam": "✅",
    "Uncertain": "⚠️",
}
_VERDICT_KEYS = {
    "Scam": "verdict_scam",
    "Not a Scam": "verdict_not_a_scam",
    "Uncertain": "verdict_uncertain",
}

# key_reasons[].source -> a small tag appended to that reason line, so a
# reader can see at a glance which evidence a unified verdict drew on.
# Shared for the same reason as verdict_style() above: without this, the
# private-DM and business-owner-DM renderers silently drifted apart on
# which sources get tagged (confirmed by /code-review - file_evidence
# was tagged in one and not the other). Plain emoji, not text - no
# translation needed.
SOURCE_TAGS = {
    "link_evidence": " 🔗",
    "file_evidence": " 📄",
}


def verdict_style(verdict: str | None, lang: str = DEFAULT_LANG) -> tuple[str, str]:
    icon = _VERDICT_ICONS.get(verdict, "⚪")
    key = _VERDICT_KEYS.get(verdict, "verdict_unknown")
    return icon, t(lang, key)


def risk_style(risk_percentage: int | None, lang: str = DEFAULT_LANG) -> tuple[str, str]:
    if risk_percentage is None:
        return "⚪", t(lang, "risk_unknown")
    if risk_percentage <= 30:
        return "🟢", t(lang, "risk_low")
    if risk_percentage <= 60:
        return "🟠", t(lang, "risk_medium")
    return "🔴", t(lang, "risk_high")
