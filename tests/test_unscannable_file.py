"""
tests/test_unscannable_file.py
================================
A file whose bytes could not be read must read as UNVERIFIED, never safe.

Live report (2026-10-07): a 21.2MB "Salary adjustments will take effect in
November 2026.xlsx.z" sent with the caption "Please view this on a
computer." produced TWO replies. The file handler said "We couldn't finish
scanning this file right now. Please try again in a moment." The unified
text+file path then swallowed the same failure, carried on with
file_verdict=None ("no attachment"), and replied "VERDICT: SAFE /
LEGITIMATE, 0% LOW RISK" under TYPE: text+file.

Three defects stacked: the failure was swallowed instead of reported; the
size check ran after get_file, which the cloud Bot API refuses for large
files, so it was never reached; and the free offline filename check never
ran because it lived after the download - though it flags exactly this name
as an archive disguised as a spreadsheet.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from telegram.error import BadRequest

from bot.detectors.file.scanner import (
    MAX_DOWNLOAD_BYTES, FileTooLargeError, download_and_hash, unscannable_file_result,
)
from bot.handlers.file_handler import _classify_file_result, handle_file

REPORTED_NAME = "Salary adjustments will take effect in November 2026.xlsx.z"


# --- download_and_hash: the size check must actually be reachable ----------


@pytest.mark.asyncio
async def test_an_oversized_declared_size_is_refused_before_any_api_call():
    context = MagicMock()
    context.bot.get_file = AsyncMock()

    with pytest.raises(FileTooLargeError):
        await download_and_hash(context, "fid", REPORTED_NAME, int(21.2 * 1024 * 1024))

    context.bot.get_file.assert_not_awaited()


@pytest.mark.asyncio
async def test_telegrams_own_refusal_of_a_big_file_becomes_file_too_large():
    # The cloud Bot API refuses getFile for large files outright, so the old
    # check on file_info.file_size was never reached for the files it was
    # written for.
    context = MagicMock()
    context.bot.get_file = AsyncMock(side_effect=BadRequest("File is too big"))

    with pytest.raises(FileTooLargeError):
        await download_and_hash(context, "fid", "x.zip", None)


@pytest.mark.asyncio
async def test_other_bad_requests_still_propagate_unchanged():
    context = MagicMock()
    context.bot.get_file = AsyncMock(side_effect=BadRequest("Wrong file_id"))

    with pytest.raises(BadRequest):
        await download_and_hash(context, "fid", "x.zip", 1024)


# --- classification: unverified, never safe ---------------------------------


def test_the_reported_file_is_not_safe_and_says_why():
    level, pct, reasons = _classify_file_result(unscannable_file_result(REPORTED_NAME, "too_large"))

    assert level != "safe"
    assert pct is None or pct >= 25
    joined = " ".join(reasons)
    assert "too large" in joined
    # The offline filename check still ran and caught the disguise.
    assert ".xlsx" in joined and ".z" in joined
    # It must NOT claim the structure looked fine - it was never read.
    assert "structure" not in joined


def test_an_unscannable_file_with_an_innocent_name_is_unverified_not_safe():
    level, pct, reasons = _classify_file_result(unscannable_file_result("holiday_photos.zip", "too_large"))

    assert (level, pct) == ("uncertain", None)
    assert any("too large" in r for r in reasons)


# --- the direct file reply ---------------------------------------------------


@pytest.mark.asyncio
async def test_handle_file_reports_an_oversized_file_instead_of_saying_try_again(fake_subscription_store):
    update = MagicMock()
    update.message.document = MagicMock(file_name=REPORTED_NAME, file_id="fid", file_size=int(21.2 * 1024 * 1024))
    update.effective_user = MagicMock(id=7)
    sent = MagicMock()
    sent.edit_text = AsyncMock()
    update.message.reply_text = AsyncMock(return_value=sent)
    context = MagicMock()
    context.user_data = {}

    with patch("bot.handlers.file_handler.download_and_hash", AsyncMock(side_effect=FileTooLargeError("big"))), \
         patch("bot.handlers.file_handler.animate_status", AsyncMock()):
        await handle_file(update, context)

    reply = sent.edit_text.await_args.args[0]
    assert "try again" not in reply                  # permanent, not transient
    assert "too large" in reply
    assert "SAFE / LEGITIMATE" not in reply
    # Nothing was scanned, so nothing may be charged.
    assert fake_subscription_store._row(7)["files_used"] == 0


# --- the unified text+file path (where the reported SAFE came from) --------


@pytest.mark.asyncio
async def test_the_text_path_no_longer_swallows_a_failed_file_scan():
    from bot.handlers import text_handler as th

    document = MagicMock(file_name=REPORTED_NAME, file_size=int(21.2 * 1024 * 1024))
    with patch.object(th, "check_message_full", AsyncMock(return_value=[])), \
         patch.object(th, "_scan_attached_file", AsyncMock(side_effect=FileTooLargeError("big"))):
        _links, file_verdict = await th._gather_check_verdicts(
            "Please view this on a computer.", [], document, MagicMock())

    assert file_verdict is not None                  # None meant "no attachment"
    assert file_verdict["scan_error"] == "too_large"


@pytest.mark.asyncio
async def test_a_harmless_caption_cannot_make_an_unscanned_attachment_safe(monkeypatch):
    # The exact reported chain: Gemini reads the caption as innocent and
    # answers "Not a Scam"; the attachment could not be checked.
    import bot.context_engine.context_engine as ce

    response = MagicMock()
    response.text = json.dumps({"verdict": "Not a Scam", "risk_percentage": 0,
                                "key_reasons": [], "recommendations": []})
    response.usage_metadata = None
    client = MagicMock()
    client.aio.models.generate_content = AsyncMock(return_value=response)
    monkeypatch.setattr(ce, "_primary_pool", [client])

    result = await ce.analyze_unified(
        "Please view this on a computer.", {"suspicious": False, "matches": []}, [],
        file_verdict=unscannable_file_result(REPORTED_NAME, "too_large"),
    )

    assert result["verdict"] != "Not a Scam"
    assert any("too large" in r["text"] for r in result["key_reasons"])


def test_the_download_cap_matches_what_the_messages_say():
    # reason_file_too_large says "over 20 MB"; keep the constant honest.
    assert MAX_DOWNLOAD_BYTES == 20 * 1024 * 1024


# --- Option B (decision court, 2026-10-07) ------------------------------------
#
# A live malware file - the 21.2MB .xlsx.z above - was too large to download,
# so the only signal left was its name: score 30, an orange "Uncertain". A
# deliberate disguise AND no way to check the bytes are two independent
# warning signs; together they now read as high risk. Three conditions bound
# it: only for unscannable files, only for deceptive names, and worded as
# "cannot verify" rather than "malware".

from bot.detectors.file.file_risk import file_risk, is_unscannable_disguise  # noqa: E402
from bot.response.risk_scale import HIGH_FROM  # noqa: E402


def test_the_reported_file_is_now_high_risk():
    level, pct = file_risk(unscannable_file_result(REPORTED_NAME, "too_large"))

    assert level == "dangerous"
    assert pct >= HIGH_FROM


@pytest.mark.parametrize("name", [
    "invoice.pdf.exe",           # executable disguise: already high, goes higher
    "photo.jpg.scr",             # any document-like inner + executable outer
    "Report.xlsx.z",             # the reported malware shape
    "contract.pdf.rar",
    "statement.docx.zip",
])
def test_every_deceptive_double_extension_is_high_when_unscannable(name):
    level, pct = file_risk(unscannable_file_result(name, "too_large"))
    assert level == "dangerous" and pct >= HIGH_FROM
    assert pct <= 99


def test_condition_1_a_scanned_file_is_never_affected():
    # The boost exists only for files whose bytes could not be read. A file
    # that WAS scanned keeps its own verdict: a disguised name VirusTotal
    # vouches for is still just a medium warning.
    scanned = {
        "checked": True, "found": True, "malicious": 0, "total": 70,
        "filename_warning_key": "filename_warning_double_extension_archive",
        "filename_warning_params": {"outer_ext": "z", "inner_ext": "xlsx"},
        "filename_risk_score": 30, "content_findings": [],
    }

    assert not is_unscannable_disguise(scanned)
    assert file_risk(scanned) == ("suspicious", 30)


def test_condition_1b_an_unscanned_file_that_never_hit_scan_file_is_not_boosted():
    # Same disguised name, no scan_error: it came through scan_file with a
    # VirusTotal "never seen" answer, which is a different situation.
    result = {
        "checked": True, "found": False, "malicious": 0, "content_findings": [],
        "filename_warning_key": "filename_warning_double_extension_archive",
        "filename_warning_params": {"outer_ext": "z", "inner_ext": "xlsx"},
        "filename_risk_score": 30,
    }
    assert file_risk(result) == ("suspicious", 30)


# --- review fixes (independent pre-push review, 2026-10-07) ----------------------


@pytest.mark.parametrize("name", [
    "data.csv.gz", "export.csv.xz", "syslog.txt.gz", "notes.txt.z",
    "Photos.jpg.zip", "video.mp4.zip", "book.pdf.tar", "backup.xlsx.gz",
])
def test_routine_compressed_files_over_20mb_are_not_called_scams(name):
    # The first version put "LIKELY A SCAM / 60% HIGH RISK" on all of these.
    # gzip/xz/bzip2/tar append their extension BY DESIGN (file.csv -> .csv.gz),
    # and csv/txt/jpg/mp4 inside an archive is ordinary data.
    result = unscannable_file_result(name, "too_large")

    assert not is_unscannable_disguise(result)
    level, pct = file_risk(result)
    assert pct is None or pct < HIGH_FROM


def test_a_transient_failure_never_reads_as_a_scam():
    # "failed" (timeout, Telegram hiccup, an error inside scan_file) on a small
    # photos.jpg.zip used to become 60% high risk. Only a genuine "too_large"
    # counts: nothing is known about a file that merely failed to download.
    for name in ("photos.jpg.zip", "Report.xlsx.z", "invoice.pdf.exe"):
        result = unscannable_file_result(name, "failed")
        assert not is_unscannable_disguise(result)
    # The disguise still earns its ordinary medium warning - just not the boost.
    level, pct = file_risk(unscannable_file_result("Report.xlsx.z", "failed"))
    assert level == "suspicious" and pct == 30
    level, pct = file_risk(unscannable_file_result("photos.jpg.zip", "failed"))
    assert pct is None or pct < HIGH_FROM


def test_the_failure_wording_does_not_claim_a_download_problem():
    _level, _pct, reasons = _classify_file_result(unscannable_file_result("x.pdf", "failed"))
    assert "temporary problem" in " ".join(reasons)
    assert "downloaded" not in " ".join(reasons)


def test_exception_text_carries_no_exact_size():
    # The text reaches the log through tracebacks and warning lines.
    import asyncio

    context = MagicMock()
    with pytest.raises(FileTooLargeError) as caught:
        asyncio.run(download_and_hash(context, "fid", "x.zip", 22234567))
    assert "22234567" not in str(caught.value)
    assert "20971520" not in str(caught.value)


def test_a_bare_executable_that_is_too_large_is_not_an_alarm():
    # Legitimate installers routinely exceed 20MB. "setup.exe, too large"
    # must stay a medium "unverified", never an alarm.
    level, pct = file_risk(unscannable_file_result("Setup_v2.exe", "too_large"))

    assert level == "suspicious"
    assert pct < HIGH_FROM


def test_an_innocently_named_oversize_file_stays_unverified():
    assert file_risk(unscannable_file_result("holiday_photos.zip", "too_large")) == ("uncertain", None)


def test_condition_3_the_wording_says_cannot_verify_not_that_it_is_malware():
    _level, _pct, reasons = _classify_file_result(unscannable_file_result(REPORTED_NAME, "too_large"))
    first = reasons[0]

    assert "could not check" in first and "unsafe until" in first
    for overclaim in ("malware", "virus", "malicious", "VirusTotal"):
        assert overclaim not in " ".join(reasons), f"overclaims: {overclaim!r}"


@pytest.mark.asyncio
async def test_the_unified_override_does_not_falsely_claim_virustotal_confirmed_it(monkeypatch):
    # Latent bug fixed alongside B: the Scam override always said the file
    # "was independently confirmed malicious by VirusTotal", which is false
    # for a file that reached "dangerous" through local findings alone.
    import bot.context_engine.context_engine as ce

    response = MagicMock()
    response.text = json.dumps({"verdict": "Not a Scam", "risk_percentage": 0,
                                "key_reasons": [], "recommendations": []})
    response.usage_metadata = None
    client = MagicMock()
    client.aio.models.generate_content = AsyncMock(return_value=response)
    monkeypatch.setattr(ce, "_primary_pool", [client])

    result = await ce.analyze_unified(
        "Please view this on a computer.", {"suspicious": False, "matches": []}, [],
        file_verdict=unscannable_file_result(REPORTED_NAME, "too_large"),
    )

    assert result["verdict"] == "Scam"
    assert all("VirusTotal" not in r["text"] for r in result["key_reasons"])
    assert any("could not check" in r["text"] for r in result["key_reasons"])


# --- condition 2: oversize events are measurable, privately ----------------------


def test_oversize_events_are_logged_by_size_bucket_without_identifying_anything(caplog):
    import logging

    secret_name = "Sokha_Chan_passport_scan.pdf.rar"
    with caplog.at_level(logging.INFO, logger="bot.detectors.file.scanner"):
        unscannable_file_result(secret_name, "too_large", int(21.2 * 1024 * 1024))

    line = next(r.getMessage() for r in caplog.records if "[oversize-file]" in r.getMessage())
    assert "size=20-50MB" in line
    assert "disguised=True" in line
    assert "reason=too_large" in line
    assert "Sokha" not in line and "passport" not in line      # no file name
    assert "21" not in line                                     # no exact size


@pytest.mark.parametrize("size,bucket", [
    (5 * 1024 * 1024, "under-20MB"),
    (None, "unknown"), (30 * 1024 * 1024, "20-50MB"), (80 * 1024 * 1024, "50-200MB"),
    (500 * 1024 * 1024, "200MB-1GB"), (3 * 1024 ** 3, "over-1GB"),
])
def test_size_buckets(size, bucket):
    from bot.detectors.file.scanner import _size_bucket

    assert _size_bucket(size) == bucket
