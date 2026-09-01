"""
bot/verdict_style.py
======================
Shared verdict/risk display styling - used by both the private-DM reply
(text_handler.py) and the business-owner-DM notification
(url_checker/message/handler.py), so the two surfaces can never silently
diverge on what counts as "High Risk" or how a verdict is labelled.
"""

from __future__ import annotations

VERDICT_STYLES = {
    "Scam": ("⚠️", "LIKELY A SCAM"),
    "Not a Scam": ("✅", "SAFE / LEGITIMATE"),
    "Uncertain": ("⚠️", "SUSPICIOUS"),
}

# key_reasons[].source -> a small tag appended to that reason line, so a
# reader can see at a glance which evidence a unified verdict drew on.
# Shared for the same reason as VERDICT_STYLES above: without this, the
# private-DM and business-owner-DM renderers silently drifted apart on
# which sources get tagged (confirmed by /code-review - file_evidence
# was tagged in one and not the other).
SOURCE_TAGS = {
    "link_evidence": " 🔗",
    "file_evidence": " 📄",
}


def risk_style(risk_percentage: int | None) -> tuple[str, str]:
    if risk_percentage is None:
        return "⚪", "Unknown Risk"
    if risk_percentage <= 30:
        return "🟢", "Low Risk"
    if risk_percentage <= 60:
        return "🟠", "Medium Risk"
    return "🔴", "High Risk"
