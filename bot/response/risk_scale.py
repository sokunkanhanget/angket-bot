"""
bot/response/risk_scale.py
============================
The ONE definition of what a risk percentage means, shared by every scan
surface (file, link, text, Business chat).

Why this exists (2026-10-01): a live `.pdf.rar` flagged by 14 of 75
VirusTotal engines rendered "VERDICT: LIKELY A SCAM" over a green
"19% LOW RISK". Tracing it found the low/medium/high cut-offs hard-coded
in four separate modules, and the link scorer's own LEVEL cut-offs
(25 / 60) disagreeing with the BADGE cut-offs (30 / 60) - so a link at
score 25-30 read "Uncertain" over green and one at exactly 60 read "Scam"
over orange. Every one of those was the same defect: the verdict and the
badge were decided by two different rules.

The fix is structural rather than a re-tuning: a level is now DERIVED from
the band a number falls in, and a verdict word is pulled into its matching
band, so the two can no longer disagree by construction.

The cut-offs are the link scorer's existing level boundaries (25 / 60),
chosen so that no link verdict changes at all; only the badges that were
contradicting their own verdicts move. They are NOT calibrated against
labeled data - there is no labeled file or link corpus yet. Treat them as
a consistent convention, not a measured accuracy claim.
"""

from __future__ import annotations

# A score at or above MEDIUM_FROM is no longer "low"; at or above HIGH_FROM
# it is "high". Everything else in the bot must import these, never repeat
# them (tests/test_risk_scale.py greps the source to enforce that).
MEDIUM_FROM = 25
HIGH_FROM = 60

# A displayed 100% claims absolute certainty. Even a VirusTotal-confirmed
# detection is strong evidence, not proof, so nothing renders above this.
MAX_DISPLAYED = 99

LOW, MEDIUM, HIGH = "low", "medium", "high"

_LEVEL_FOR_BAND = {LOW: "safe", MEDIUM: "suspicious", HIGH: "dangerous"}
_VERDICT_FOR_BAND = {LOW: "Not a Scam", MEDIUM: "Uncertain", HIGH: "Scam"}
_BAND_FOR_VERDICT = {verdict: band for band, verdict in _VERDICT_FOR_BAND.items()}
# Inclusive bounds a number is pulled into when it must match a verdict.
_BAND_RANGE = {LOW: (0, MEDIUM_FROM - 1), MEDIUM: (MEDIUM_FROM, HIGH_FROM - 1), HIGH: (HIGH_FROM, MAX_DISPLAYED)}


def band(risk_percentage: int | None) -> str | None:
    """low / medium / high, or None when there is no number at all
    ("unverified" - nothing actually measured the risk)."""
    if risk_percentage is None:
        return None
    if risk_percentage >= HIGH_FROM:
        return HIGH
    if risk_percentage >= MEDIUM_FROM:
        return MEDIUM
    return LOW


def clamp(risk_percentage: int | None) -> int | None:
    """0..MAX_DISPLAYED, None preserved."""
    if risk_percentage is None:
        return None
    return max(0, min(MAX_DISPLAYED, int(risk_percentage)))


def level_for(risk_percentage: int) -> str:
    """safe / suspicious / dangerous for a numeric score - the level the
    file and link scorers report. Derived from the band, never decided
    separately, which is what keeps level and badge in agreement."""
    return _LEVEL_FOR_BAND[band(clamp(risk_percentage))]


def coherent_risk(verdict: str | None, risk_percentage: int | None) -> int | None:
    """The number to display beside `verdict` so the two agree.

    Gemini chooses its verdict word and its number independently and can
    return, say, "Scam" at 40%. The verdict word is treated as the primary
    judgement (it is what the evidence-reconciliation overrides act on),
    and the number is pulled into that verdict's band. Inside the band the
    number is left alone, so caps such as UNCORROBORATED_RISK_CAP (80)
    still apply exactly as before.

    None is kept only for an "Uncertain" verdict - that is the honest
    "unverified" state. A Scam / Not-a-Scam verdict with no number gets
    its band's edge, because those verdicts are claims and must show how
    strongly they are made.
    """
    target = _BAND_FOR_VERDICT.get(verdict)
    if risk_percentage is None:
        if target is None or verdict == "Uncertain":
            return None
        return _BAND_RANGE[target][0] if target != LOW else 0
    value = clamp(risk_percentage)
    if target is None:
        return value
    low, high = _BAND_RANGE[target]
    return max(low, min(high, value))
