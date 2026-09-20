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

import html
from datetime import datetime, timedelta

from bot.detectors.url.offline.lexical import URL_REGEX
from bot.response.translate import DEFAULT_LANG
from bot.response.buttons import t
from bot.config.config import DISPLAY_TIMEZONE_OFFSET_HOURS

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

# Keep one blank row above the disclaimer. Telegram does not expose
# text-centering controls through the Bot API, and a horizontal line is
# unnecessary visual noise on narrow screens.
DISCLAIMER_SPACER = ""


def format_local_datetime(utc_dt: datetime) -> str:
    """A UTC-aware datetime rendered in this project's one display
    timezone (DISPLAY_TIMEZONE_OFFSET_HOURS - see that constant's own
    docstring for why a true per-user timezone isn't something the Bot
    API can answer), as "%d %b %Y, %I:%M %p (UTC+n)".

    Extracted (2026-09-16, found by code review) after this exact
    two-line format existed independently in three places - the
    business-chat header (url_handler.py), the admin failure alert
    (health_alerts.py), and the daily-quota reset notice
    (subscription.py) - each one built by hand instead of sharing this.
    A future tweak to the format applied to only some call sites was the
    real risk that duplication carried."""
    local_dt = utc_dt + timedelta(hours=DISPLAY_TIMEZONE_OFFSET_HOURS)
    return f"{local_dt.strftime('%d %b %Y, %I:%M %p')} (UTC{DISPLAY_TIMEZONE_OFFSET_HOURS:+d})"


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


def trusted_link_notice(host: str, lang: str = DEFAULT_LANG, style: str = "html") -> str:
    """The full reply for a trusted-brand bare link, replacing the
    normal VERDICT/TYPE/KEY REASONS/WHAT TO DO template - direct user
    spec (2026-09-16): a message that's nothing but a link to a verified
    PROTECTED_BRANDS domain, confirmed safe after the real redirect
    trace, doesn't need that full treatment, quota or no quota. Every
    real caller that produces a unified verdict must check for
    unified.get("trusted_link_notice_host") and call this instead of the
    normal full-template renderer when it's set: text_handler.py's
    handle_text and handle_check, AND url_handler.py's
    handle_business_message - that last one was genuinely missed in the
    first pass (found by code review, 2026-09-16) precisely because this
    docstring didn't name it either. (A fourth caller, url_handler.py's
    now-deleted handle_url, used to reach this too via its own local
    trusted_and_safe check on the group-chat link-only path - removed
    2026-09-19 along with the rest of that dead chain, see
    url_handler.py's module docstring.)

    style matches defang_domains' own param - "html" for the HTML-parse-
    mode surfaces (private DM/business chat), "markdown" for the
    legacy-Markdown group-chat link checker.

    Real bug, found by code review (2026-09-16): the html.escape() ->
    defang_domains() order every other style="html" call site follows
    (text_handler.py's _format_list/reason_lines - see
    defang_domains' own docstring for why the order matters) was
    missing here. Currently harmless only because `host` is always a
    hand-verified PROTECTED_BRANDS domain and the fixed translated
    notice text has no HTML metacharacters today - the moment either
    changes (a future translation using "&amp;", or this function
    reused for a less-constrained host), parse_mode="HTML" rendering
    would silently break without the escape.
    """
    icon, _ = verdict_style("Not a Scam", lang)
    notice = t(lang, "trusted_link_notice").format(host=host)
    if style == "html":
        notice = html.escape(notice)
    return "\n".join([
        f"{icon} {defang_domains(notice, style=style)}",
        DISCLAIMER_SPACER,
        t(lang, "verdict_disclaimer"),
    ])


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
