"""
tests/test_oversize_log_report.py
===================================
The B7 log summariser (tools/oversize_log_report.py). Its job is to make the
decision court's "make it measurable" condition actionable, and its one
safety property is that it must notice if the log line ever starts carrying
more than the agreed fields.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "oversize_log_report", Path(__file__).resolve().parent.parent / "tools" / "oversize_log_report.py")
report = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(report)

RENDER_LINES = [
    "2026-10-08T03:01:11.402Z INFO bot.detectors.file.scanner: [oversize-file] reason=too_large size=20-50MB disguised=True",
    "2026-10-08T03:05:00.000Z INFO bot.bot: update: id=1 kind=message user=42",          # noise
    "2026-10-08T09:40:12.100Z INFO bot.detectors.file.scanner: [oversize-file] reason=too_large size=50-200MB disguised=False",
    "2026-10-08T11:00:00.500Z INFO bot.detectors.file.scanner: [oversize-file] reason=failed size=unknown disguised=False",
]


def test_counts_events_ignores_noise_and_reports_the_window():
    summary = report.summarize(RENDER_LINES)

    assert summary["total"] == 3
    assert summary["disguised"] == 1
    assert summary["reasons"] == {"too_large": 2, "failed": 1}
    assert summary["sizes"] == {"20-50MB": 1, "50-200MB": 1, "unknown": 1}
    assert summary["first"].startswith("2026-10-08T03:01")
    assert summary["last"].startswith("2026-10-08T11:00")
    assert summary["unexpected"] == 0


def test_a_line_that_carries_extra_fields_is_flagged_not_echoed():
    # If the log line ever started including a file name, that is a privacy
    # regression. It must be counted as unexpected and NEVER printed back.
    leaky = ("2026-10-08T03:01:11Z INFO x: [oversize-file] reason=too_large size=20-50MB "
             "disguised=True name=Sokha_passport.pdf.rar")
    summary = report.summarize([leaky])

    assert summary["unexpected"] == 1
    assert summary["total"] == 0
    text = report.format_report(summary)
    assert "WARNING" in text
    assert "Sokha" not in text and "passport" not in text


def test_a_disguised_event_prompts_a_review():
    text = report.format_report(report.summarize(RENDER_LINES))

    assert "1 of 3 (33%)" in text
    assert "REVIEW" in text


def test_no_events_says_so_plainly():
    text = report.format_report(report.summarize(["unrelated line", ""]))

    assert "No [oversize-file] lines found" in text


def test_it_reads_the_exact_line_the_scanner_really_writes(caplog):
    # Round trip against the REAL producer, so a future change to the log
    # format breaks this instead of silently emptying the report.
    import logging

    from bot.detectors.file.scanner import unscannable_file_result

    with caplog.at_level(logging.INFO, logger="bot.detectors.file.scanner"):
        unscannable_file_result("Salary adjustments.xlsx.z", "too_large", 30 * 1024 * 1024)

    lines = [f"2026-10-08T00:00:00Z INFO x: {record.getMessage()}" for record in caplog.records]
    summary = report.summarize(lines)

    assert summary["total"] == 1 and summary["unexpected"] == 0
    assert summary["disguised"] == 1
