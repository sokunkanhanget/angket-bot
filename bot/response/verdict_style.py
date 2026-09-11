"""
bot/response/verdict_style.py
======================
Shared verdict/risk display styling - used by both the private-DM reply
(text_handler.py) and the business-owner-DM notification
(handlers/url_handler.py), so the two surfaces can never silently
diverge on what counts as "High Risk" or how a verdict is labelled.

Both verdict_style() and risk_style() take a `lang` - the labels are
FIXED text (not something Gemini generates per call), so they're
translated once via bot/response/translate/ instead of round-tripping through the model
for a handful of words every single call. Group chat (bot/route.py's
TEXT_FILTER path) deliberately keeps calling these with lang="en" -
see text_handler.py's format_analysis_response - group replies are out
of scope for translation for now, unlike private DM/business chat.
"""

from __future__ import annotations

from bot.detectors.url.offline.lexical import URL_REGEX
from bot.response.translate import DEFAULT_LANG
from bot.response.buttons import t

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

# Direct user/teammate feedback on the reply's visual layout: a clean
# separator between the real content and the disclaimer footer, so the
# disclaimer doesn't read as just another paragraph of the verdict
# itself. Plain Unicode box-drawing characters - render identically,
# with no escaping needed, in both this project's parse modes
# (Markdown: pipeline.py/file_handler.py/url_handler.py, including its
# business-owner notification; HTML: text_handler.py's private-DM
# reply only - confirmed live 2026-09-10 while checking whether
# spoiler/underline/strikethrough formatting could be added: those
# three only work under HTML, not legacy Markdown, so they're
# currently only possible in text_handler.py's reply, not the other
# three surfaces), unlike most punctuation.
# A stray divider was removed from a different, awkward position in an
# earlier session (between the disclaimer and the rest of the reply) -
# this is deliberately just ABOVE the disclaimer specifically, not a
# repeat of that. Iterated live over several lengths (46 -> 20 -> 28 ->
# 18, 2026-09-10) via direct user feedback checking real replies on
# both mobile and desktop Telegram clients - 18 is what read well on
# both. See this module's own note above (and bot/config/config.py's
# DISPLAY_TIMEZONE_OFFSET_HOURS docstring) for the general shape of
# this problem: the Bot API gives no per-recipient device/client
# signal at all, so one fixed length is genuinely the only lever
# available - not a compromise made for lack of trying.
SECTION_DIVIDER = "─" * 18


def defang_domains(text: str, style: str = "html") -> str:
    """Wraps any URL/domain-like substring in a non-clickable code span,
    direct user spec (2026-09-11): a reply warning about a link
    shouldn't itself hand the reader a one-tap way to open it. Reuses
    URL_REGEX - the SAME pattern this whole project already uses to
    decide what counts as a link when SCANNING - so anything worth
    flagging as a link when checking is also worth not making clickable
    when displaying it, one definition for both.

    style="html": wraps with <code>...</code> - call this AFTER
    html.escape() has already run on the surrounding text, not before.
    Domain characters (letters/digits/dots/hyphens/colons) are untouched
    by escaping, so matching against already-escaped text is safe, and
    the <code> tags this adds are real markup, not further escaped.
    style="markdown": wraps with backticks instead, for the legacy-
    Markdown surfaces (pipeline.py/file_handler.py/url_handler.py's
    business notification)."""
    wrap = (lambda s: f"<code>{s}</code>") if style == "html" else (lambda s: f"`{s}`")
    return URL_REGEX.sub(lambda m: wrap(m.group(0)), text)


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


def summary_sentence(verdict: str | None, risk_percentage: int | None, lang: str = DEFAULT_LANG) -> str:
    """The one-line sentence right under VERDICT/TYPE (e.g. "This message
    shows strong signs of being unsafe."). Moved here from text_handler.py
    so pipeline.py and file_handler.py can share it too, now that every
    scan surface (text/link/file/business) uses the same reply shape -
    text_handler.py importing this from here instead of defining it
    locally avoids a circular import (pipeline.py is imported BY
    url_handler.py, which text_handler.py also imports from)."""
    if verdict == "Scam":
        if risk_percentage is not None and risk_percentage <= 60:
            return t(lang, "summary_warning_signs")
        return t(lang, "summary_strong_unsafe")
    if verdict == "Not a Scam":
        if risk_percentage is not None and risk_percentage > 30:
            return t(lang, "summary_warning_signs")
        return t(lang, "summary_no_indicators")
    if risk_percentage is not None and risk_percentage > 60:
        return t(lang, "summary_strong_unsafe")
    if risk_percentage is not None and risk_percentage > 30:
        return t(lang, "summary_warning_signs")
    # risk_percentage is None here only for file_handler.py's genuine
    # no-signal case (no VT match/reachability AND no filename warning) -
    # a real, confirmed bug this fixes live: that case's verdict label is
    # "SUSPICIOUS" (Uncertain), so falling through to "no indicators
    # detected" directly contradicted it. risk_style(None) already shows
    # "⚪ Unknown Risk" distinctly for the same reason - this matches that.
    if risk_percentage is None:
        return t(lang, "summary_uncertain_no_signal")
    return t(lang, "summary_no_indicators")


# pipeline.py (link checker) and file_handler.py (file scanner) each have
# their own internal risk "level" vocabulary (dangerous/suspicious/safe,
# plus file's extra "uncertain" for a genuine no-signal case) - this maps
# either onto the SAME three-way verdict vocabulary (Scam/Not a Scam/
# Uncertain) verdict_style() already uses for text/business checks, so
# all four surfaces render an identical VERDICT line. "uncertain" (file
# only) maps to "Uncertain" too: paired with risk_percentage=None, that
# renders as "⚪ Unknown Risk" via risk_style(None) - genuinely distinct
# from "suspicious"'s real, numeric-percentage "Uncertain" case, not a
# forced conflation of two different situations.
LEVEL_TO_VERDICT = {
    "dangerous": "Scam",
    "suspicious": "Uncertain",
    "safe": "Not a Scam",
    "uncertain": "Uncertain",
}


def scan_type_label(has_text: bool, has_link: bool, has_file: bool) -> str:
    """The "📁 TYPE:" line's value - which of text/link/file this
    particular check actually covered. Direct user spec: seven exact
    combinations, not a generic sorted join (a bare link+file with no
    real text reads "file+link", not "link+file", while text always
    sorts first when present) - see the caller-supplied booleans'
    docstrings at each call site for how "has_text" in particular is
    decided (a message that's ONLY a pasted link does not count)."""
    if has_text and has_link and has_file:
        return "all"
    if has_text and has_link:
        return "text+link"
    if has_text and has_file:
        return "text+file"
    if has_link and has_file:
        return "file+link"
    if has_text:
        return "text"
    if has_link:
        return "link"
    if has_file:
        return "file"
    return "text"  # degenerate/unreachable in practice - every caller checks something
