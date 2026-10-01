"""
tests/test_risk_scale.py
==========================
One invariant, checked on every surface that shows a verdict next to a
risk badge: the two must never contradict each other.

Origin (2026-10-01): a live `.pdf.rar` flagged by 14 of 75 VirusTotal
engines rendered "VERDICT: LIKELY A SCAM" directly above a green
"19% LOW RISK". Measuring afterwards showed the same defect class on the
link side too - a score of 25-30 read "Uncertain" over a green badge, and
exactly 60 read "Scam" over an orange one - because the level cut-offs
(25/60) and the badge cut-offs (30/60) were defined in different places
and silently disagreed. The low/medium/high cut-offs were copied in four
separate modules.

These tests sweep whole score ranges rather than pinning single numbers,
so a future threshold change anywhere must keep every surface agreeing.
"""

from __future__ import annotations

import pytest

from bot.response.verdict_style import LEVEL_TO_VERDICT, risk_style

# Which badge colour each verdict is allowed to sit above.
_ALLOWED_ICON = {"Scam": "🔴", "Uncertain": "🟠", "Not a Scam": "🟢"}


def _assert_coherent(verdict: str, pct: int | None, where: str) -> None:
    icon, _label = risk_style(pct)
    if pct is None:
        # Only an Uncertain verdict may have no number ("unverified").
        assert verdict == "Uncertain", f"{where}: {verdict} with no risk number"
        return
    assert icon == _ALLOWED_ICON[verdict], (
        f"{where}: verdict {verdict!r} rendered over a {icon} badge at {pct}%"
    )


# --- links -------------------------------------------------------------


def test_link_level_and_badge_agree_for_every_score():
    from bot.detectors.url import pipeline
    from bot.detectors.url.offline.lexical import _verdict_labels

    for score in range(0, 151):
        level = _verdict_labels(score)[0]
        pct, _ = pipeline._risk_percent_and_label(score)
        _assert_coherent(LEVEL_TO_VERDICT[level], pct, f"link score {score}")


# --- files -------------------------------------------------------------


def _vt(malicious, *, checked=True, found=True, total=75, **extra):
    return {
        "checked": checked, "found": found, "malicious": malicious, "total": total,
        "top_engines": {"Microsoft": "Trojan:Win32/Test"},
        "filename_warning_key": None, "filename_warning_params": {},
        "filename_risk_score": 0, **extra,
    }


_FILENAME_CASES = [
    (None, {}, 0),
    ("filename_warning_double_extension_archive", {"outer_ext": "rar", "inner_ext": "pdf"}, None),
    ("filename_warning_double_extension_executable", {"outer_ext": "exe", "inner_ext": "pdf"}, None),
    ("filename_warning_lone_executable", {"ext": "apk"}, None),
]


@pytest.mark.parametrize("malicious", [0, 1, 2, 3, 5, 9, 10, 14, 40, 75])
@pytest.mark.parametrize("key,params,_", _FILENAME_CASES)
def test_file_verdict_and_badge_agree_when_virustotal_has_an_answer(malicious, key, params, _):
    from bot.detectors.file.offline.filename_check import check_filename
    from bot.handlers.file_handler import _classify_file_result

    score = 0
    if key:
        name = {"filename_warning_double_extension_archive": "a.pdf.rar",
                "filename_warning_double_extension_executable": "a.pdf.exe",
                "filename_warning_lone_executable": "a.apk"}[key]
        score = check_filename(name)[0]
    result = _vt(malicious, filename_warning_key=key, filename_warning_params=params,
                 filename_risk_score=score)

    level, pct, _reasons = _classify_file_result(result)
    _assert_coherent(LEVEL_TO_VERDICT[level], pct, f"file {malicious}/75 + {key}")


@pytest.mark.parametrize("checked,found", [(False, False), (True, False)])
@pytest.mark.parametrize("key,params,_", _FILENAME_CASES)
def test_file_verdict_and_badge_agree_without_a_virustotal_answer(checked, found, key, params, _):
    from bot.detectors.file.offline.filename_check import check_filename
    from bot.handlers.file_handler import _classify_file_result

    score = 0
    if key:
        name = {"filename_warning_double_extension_archive": "a.pdf.rar",
                "filename_warning_double_extension_executable": "a.pdf.exe",
                "filename_warning_lone_executable": "a.apk"}[key]
        score = check_filename(name)[0]
    result = _vt(0, checked=checked, found=found, filename_warning_key=key,
                 filename_warning_params=params, filename_risk_score=score)

    level, pct, _reasons = _classify_file_result(result)
    _assert_coherent(LEVEL_TO_VERDICT[level], pct, f"file no-VT checked={checked} + {key}")


def test_file_risk_never_drops_as_more_engines_flag_it():
    from bot.handlers.file_handler import _classify_file_result

    previous = -1
    for malicious in range(0, 76):
        _level, pct, _ = _classify_file_result(_vt(malicious))
        pct = pct or 0
        assert pct >= previous, f"risk dropped at {malicious} engines: {previous} -> {pct}"
        previous = pct


# --- text / unified verdicts (Gemini + offline fallback + overrides) -----


@pytest.mark.parametrize("verdict", ["Scam", "Uncertain", "Not a Scam"])
def test_unified_results_are_made_coherent_for_any_number_gemini_returns(verdict):
    # Gemini picks the verdict word AND the number independently, so it can
    # return e.g. "Scam" with 40%. Whatever it returns, the final dict must
    # render without a contradiction.
    from bot.response.risk_scale import coherent_risk

    for pct in [None, 0, 10, 24, 25, 30, 45, 59, 60, 61, 80, 95, 100]:
        fixed = coherent_risk(verdict, pct)
        if pct is None and verdict != "Uncertain":
            # A Scam/Not-a-Scam verdict must always carry a number.
            assert fixed is not None
        if fixed is None:
            assert verdict == "Uncertain"
            continue
        _assert_coherent(verdict, fixed, f"unified {verdict} {pct}%")


def test_no_surface_ever_claims_absolute_certainty():
    from bot.response.risk_scale import coherent_risk

    assert coherent_risk("Scam", 100) <= 99


# --- one source of truth -------------------------------------------------


def test_the_cut_offs_are_defined_in_exactly_one_place():
    # Four modules used to hard-code their own `<= 30` / `<= 60` buckets.
    # Grep the real source so a reintroduced copy fails loudly.
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent / "bot"
    offenders = []
    pattern = re.compile(r"(risk_percentage|pct|score)\s*(<=|<|>=|>)\s*(24|25|30|59|60|61)\b")
    for path in root.rglob("*.py"):
        if path.name == "risk_scale.py":
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#", 1)[0]
            if pattern.search(code):
                offenders.append(f"{path.relative_to(root.parent)}:{lineno}: {line.strip()}")
    assert not offenders, "risk cut-off hard-coded outside risk_scale.py:\n" + "\n".join(offenders)
