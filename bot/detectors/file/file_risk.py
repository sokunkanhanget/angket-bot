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


# How much a deceptive filename adds when the file could not be scanned at
# all (decision court, option B, 2026-10-07). A live malware file - a 21.2MB
# "Salary adjustments ... .xlsx.z" - was too large for the Bot API to hand
# over, so the only signal left was the name, which scored 30 (medium) and
# rendered as an orange "Uncertain". Two independent warning signs together
# - a deliberate disguise AND no way to check the bytes - are stronger than
# either alone, and oversizing is a known way to slip past scanners that
# skip large files (MITRE ATT&CK T1027.001, cited from memory, not checked
# this session - treated as a risk, not a finding).
UNSCANNABLE_DISGUISE_BOOST = 30


# Which double-extension disguises are strong enough to lift an unscannable
# file to high risk. Narrowed on 2026-10-07 after an independent review
# reproduced that the first version (any document-like inner extension, any
# archive outer) put a "LIKELY A SCAM" header on routine files over 20MB:
# data.csv.gz, export.csv.xz, syslog.txt.gz, Photos.jpg.zip, video.mp4.zip,
# book.pdf.tar. Two real conventions explain most of them:
#   - gzip/bzip2/xz/tar APPEND their extension to the original name by
#     design (file.csv -> file.csv.gz), so `.csv.gz` is the tool working,
#     not a disguise;
#   - csv/txt/jpg/mp4 inside an archive is ordinary data, not a lure.
# What remains is the actual lure class: an Office/PDF "document" that is
# really a zip/rar/7z/z archive (the reported malware was `.xlsx.z`).
_LURE_INNER = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"})
_LURE_ARCHIVE_OUTER = frozenset({"zip", "rar", "7z", "z"})


def is_unscannable_disguise(result: dict) -> bool:
    """True only for a file that could not be read because it was TOO LARGE
    AND whose name is a strong, deliberate disguise.

    Every limit here is a court condition or a reviewed refinement:
    - never for a file that WAS scanned: a scanned file's own verdict
      stands;
    - only scan_error == "too_large". A transient "failed" (a timeout, a
      Telegram hiccup) on a 2MB photos.jpg.zip must not read as a scam;
    - not for a bare executable extension: legitimate installers routinely
      exceed 20MB, so "setup.exe, too large" stays a medium "unverified";
    - an EXECUTABLE disguise (invoice.pdf.exe) always counts, but an ARCHIVE
      disguise only for the document-lure shape above.

    Known remaining false positives, accepted deliberately: a genuine
    over-20MB `scan.pdf.7z` or `report.xlsx.zip` from a colleague. They are
    what the `[oversize-file]` log (ledger B7) exists to measure.
    """
    if result.get("scan_error") != "too_large":
        return False
    key = result.get("filename_warning_key") or ""
    if key == "filename_warning_double_extension_executable":
        return True
    if key != "filename_warning_double_extension_archive":
        return False
    params = result.get("filename_warning_params") or {}
    return params.get("inner_ext") in _LURE_INNER and params.get("outer_ext") in _LURE_ARCHIVE_OUTER


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

    if is_unscannable_disguise(result):
        pct = risk_scale.clamp(max(risk_scale.HIGH_FROM, local + UNSCANNABLE_DISGUISE_BOOST))
        return risk_scale.level_for(pct), pct
    if local >= risk_scale.MEDIUM_FROM:
        pct = risk_scale.clamp(local)
        return risk_scale.level_for(pct), pct
    return "uncertain", None
