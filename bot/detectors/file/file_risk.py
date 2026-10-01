"""
bot/detectors/file/file_risk.py
=================================
The one place a scanned file's (level, risk_percentage) is decided. Pure
and language-free, so both renderers - handlers/file_handler.py (the
direct file reply) and context_engine.py (a file attached to a message in
private DM / Business chat) - reach the same verdict for the same file.
Before 2026-10-01 they disagreed: the direct reply used an engine ratio
and the unified fallback used "100% if any engine flags it".

Inputs, all already on a scan_file() result dict:
  - VirusTotal: checked / found / malicious
  - filename heuristic: filename_risk_score
  - local content inspection: content_findings, a list of
    {"score", "key", "params"} from offline/content_check.py

Every number lives on bot/response/risk_scale.py's shared bands, and the
level is DERIVED from the number - so a file's verdict and its badge
cannot disagree.
"""

from __future__ import annotations

from bot.response import risk_scale

# (minimum engines, base risk). The same 1 / 2+ / 5+ count tiers
# threat_intel.score() already applies to the link side of the same
# VirusTotal signal, plus a 10+ tier. NOT a ratio: an engine ratio answers
# "what fraction of vendors flagged it", and real malware commonly sits at
# only 10-30% of ~75 engines - that is how 14/75 rendered as "19% LOW
# RISK" under a Scam verdict. A lone detection lands in the MEDIUM band on
# purpose: single-engine hits are the classic VirusTotal false-positive
# shape. These tiers are a convention, not calibrated against labeled data.
_ENGINE_TIERS = ((10, 95), (5, 85), (2, 70), (1, 45))


def engine_risk(malicious: int) -> int:
    for minimum, risk in _ENGINE_TIERS:
        if malicious >= minimum:
            return risk
    return 0


def local_score(result: dict) -> int:
    """Strongest offline signal - filename heuristic or content inspection.
    Max, not a sum: two weak heuristics about the same file are not twice
    the evidence."""
    scores = [result.get("filename_risk_score", 0) or 0]
    scores.extend(finding.get("score", 0) for finding in result.get("content_findings") or [])
    return max(scores)


def has_antivirus_answer(result: dict) -> bool:
    """True only when VirusTotal both answered AND knew this exact file.
    "Unreachable" and "never seen this hash" are both NOT an answer - and
    "never seen" is precisely what brand-new or repacked malware looks
    like, so it must never be read as evidence of safety.

    `found` alone decides it: virustotal.py only ever sets found=True on a
    real answer (always alongside checked=True), so an explicit
    checked=False is the only thing that can override it."""
    return bool(result.get("found")) and result.get("checked", True) is not False


def file_risk(result: dict) -> tuple[str, int | None]:
    """(level, risk_percentage).

    level is safe / suspicious / dangerous, derived from the number, or
    "uncertain" with risk None when nothing actually vouches for the file:
    no antivirus answer and no offline signal strong enough to stand on
    its own. That "unverified" state replaced a flat "safe, 0%" on
    2026-10-01 - the old rule reported any file VirusTotal could not vouch
    for, with an innocuous name, as "Not a Scam" (e.g. a repacked
    `salary_slip.rar`), which is exactly where new malware hides.
    """
    local = local_score(result)

    if has_antivirus_answer(result):
        malicious = result.get("malicious", 0) or 0
        if malicious > 0:
            # Offline evidence is independent corroboration; halved so it
            # can lift a lone detection into the high band but cannot by
            # itself dominate an antivirus result.
            pct = risk_scale.clamp(engine_risk(malicious) + local // 2)
            return risk_scale.level_for(pct), pct
        if local:
            # The antivirus engines vouch for these exact bytes, but the
            # file still carries its own warning signs (a disguise, macros,
            # an executable inside an archive).
            pct = risk_scale.clamp(local)
            return risk_scale.level_for(pct), pct
        return "safe", 0

    if local >= risk_scale.MEDIUM_FROM:
        pct = risk_scale.clamp(local)
        return risk_scale.level_for(pct), pct
    return "uncertain", None
