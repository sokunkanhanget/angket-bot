"""
tests/test_file_handler.py
============================
Tests for handle_file - the direct (non-Business) file-scan path. No
buttons anywhere any more (direct user spec - a plain verdict reply,
same VERDICT/TYPE/risk/reasons/what-to-do/disclaimer shape text/link
checks use), so this covers reply CONTENT only, not reply_markup.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bot.handlers.file_handler import handle_file
from bot.response.buttons import t
from bot.storage import subscription
from bot.response.verdict_style import SECTION_DIVIDER


def _file_update(lang: str | None = None, file_name: str = "invoice.pdf"):
    update = MagicMock()
    update.message.document = MagicMock(file_name=file_name, file_id="fake-file-id")
    update.message.message_id = 42
    update.effective_user = MagicMock(id=7)

    sent = MagicMock()
    sent.message_id = 99
    sent.edit_text = AsyncMock()
    update.message.reply_text = AsyncMock(return_value=sent)

    context = MagicMock()
    context.user_data = {"lang": lang} if lang else {}
    return update, context, sent


@pytest.mark.asyncio
async def test_clean_scan_reports_safe_with_the_shared_reply_shape():
    update, context, sent = _file_update()

    with patch("bot.handlers.file_handler.download_and_hash", AsyncMock(return_value="a" * 64)), \
         patch("bot.handlers.file_handler.scan_file", AsyncMock(return_value={
             "checked": True, "found": True, "malicious": 0, "suspicious": 0, "harmless": 70,
             "undetected": 5, "total": 75,
             "top_engines": {"Microsoft": "Clean", "Kaspersky": "Clean", "BitDefender": "Clean"},
             "filename_warning": None, "filename_risk_score": 0,
         })), \
         patch("bot.handlers.file_handler.log_scan"):
        await handle_file(update, context)

    assert "reply_markup" not in sent.edit_text.call_args.kwargs  # direct user spec: no buttons
    reply = sent.edit_text.call_args.args[0]
    assert "SAFE / LEGITIMATE" in reply
    assert "📁 *TYPE: file*" in reply
    assert f"{SECTION_DIVIDER}\nⓘ Angket Bot may occasionally make mistakes." in reply


@pytest.mark.asyncio
async def test_malicious_scan_reports_a_scam_verdict():
    update, context, sent = _file_update(lang="km")

    with patch("bot.handlers.file_handler.download_and_hash", AsyncMock(return_value="b" * 64)), \
         patch("bot.handlers.file_handler.scan_file", AsyncMock(return_value={
             "checked": True, "found": True, "malicious": 40, "suspicious": 2, "harmless": 20,
             "undetected": 13, "total": 75,
             "top_engines": {"Microsoft": "Trojan", "Kaspersky": "Trojan", "BitDefender": "Trojan"},
             "filename_warning": None, "filename_risk_score": 0,
         })), \
         patch("bot.handlers.file_handler.log_scan"):
        await handle_file(update, context)

    assert "reply_markup" not in sent.edit_text.call_args.kwargs
    reply = sent.edit_text.call_args.args[0]
    assert t("km", "verdict_scam") in reply
    assert t("km", "type_label") in reply


@pytest.mark.asyncio
async def test_unknown_signature_with_clean_filename_reports_safe():
    # checked=True here specifically means VT itself confirmed it has
    # never seen this hash - a real (if weak) answer, distinct from
    # "VT couldn't be reached" below, which used to be indistinguishable.
    # 2026-09-11 spec: no VT signal AND a clean filename (no disguise, no
    # risky extension) is "safe" (nothing we checked flagged it), not the
    # old blanket "uncertain, N/A risk" - a single unavailable/silent
    # service shouldn't blank out a real verdict when the offline
    # filename check already ran and found nothing.
    update, context, sent = _file_update()

    with patch("bot.handlers.file_handler.download_and_hash", AsyncMock(return_value="c" * 64)), \
         patch("bot.handlers.file_handler.scan_file", AsyncMock(return_value={
             "checked": True, "found": False, "filename_warning": None, "filename_risk_score": 0,
         })), \
         patch("bot.handlers.file_handler.log_scan"):
        await handle_file(update, context)

    reply = sent.edit_text.call_args.args[0]
    assert "SAFE / LEGITIMATE" in reply
    assert "never been seen by VirusTotal" in reply
    assert "No filename red flags were found either" in reply


@pytest.mark.asyncio
async def test_virustotal_outage_with_clean_filename_still_reports_safe():
    # Real fix, matching the text/link checkers' own resilience: before
    # this session, ANY scan_file failure (a genuine VT outage included)
    # showed a bare "couldn't scan, try again later" with zero signal.
    # Now scan_vt_hash() itself never raises - a VT outage comes back as
    # checked=False, and the handler builds a real verdict from whatever
    # offline evidence remains. 2026-09-11 spec: a clean filename here
    # means "safe" (the filename check ran and found nothing), not the
    # old blanket "uncertain, N/A risk" that treated VT's own outage as
    # if nothing at all had been checked.
    update, context, sent = _file_update()

    with patch("bot.handlers.file_handler.download_and_hash", AsyncMock(return_value="e" * 64)), \
         patch("bot.handlers.file_handler.scan_file", AsyncMock(return_value={
             "checked": False, "found": False, "error": "503 UNAVAILABLE",
             "filename_warning": None, "filename_risk_score": 0,
         })), \
         patch("bot.handlers.file_handler.log_scan") as mock_log:
        await handle_file(update, context)

    reply = sent.edit_text.call_args.args[0]
    assert "SAFE / LEGITIMATE" in reply
    assert "based on the file name only" in reply
    assert "VirusTotal" not in reply  # 2026-09-11 spec: don't name the failing backend service to the user
    mock_log.assert_called_once()  # this DID complete a real (degraded) scan, unlike a download failure


@pytest.mark.asyncio
async def test_virustotal_outage_with_a_bare_executable_flags_it_suspicious():
    # New offline signal (2026-09-11 spec): an executable/script sent
    # with no document-like disguise at all still gets flagged on its
    # own - a bare ".exe"/".apk" is a real scam vector (fake banking
    # apps, fake installers) even with zero VirusTotal signal and no
    # double-extension trick.
    update, context, sent = _file_update(file_name="totally_legit_app.apk")

    with patch("bot.handlers.file_handler.download_and_hash", AsyncMock(return_value="g" * 64)), \
         patch("bot.handlers.file_handler.scan_file", AsyncMock(return_value={
             "checked": False, "found": False, "error": "503 UNAVAILABLE",
             "filename_warning": "This is a '.apk' executable/script file — a common "
                                  "malware vector, especially when unsolicited.",
             "filename_risk_score": 35,
         })), \
         patch("bot.handlers.file_handler.log_scan"):
        await handle_file(update, context)

    reply = sent.edit_text.call_args.args[0]
    assert "SUSPICIOUS" in reply
    assert "executable/script file" in reply


@pytest.mark.asyncio
async def test_virustotal_outage_with_a_disguised_filename_still_flags_it():
    # The other half of the same fix: even with VT fully down, the
    # filename heuristic alone is real, independent, local evidence -
    # it must not get silently dropped just because VT had nothing.
    update, context, sent = _file_update()

    with patch("bot.handlers.file_handler.download_and_hash", AsyncMock(return_value="f" * 64)), \
         patch("bot.handlers.file_handler.scan_file", AsyncMock(return_value={
             "checked": False, "found": False, "error": "503 UNAVAILABLE",
             "filename_warning": "File name disguises an executable ('.exe') behind a '.pdf' extension.",
             "filename_risk_score": 50,
         })), \
         patch("bot.handlers.file_handler.log_scan"):
        await handle_file(update, context)

    reply = sent.edit_text.call_args.args[0]
    assert "LIKELY A SCAM" in reply
    assert "disguises an executable" in reply


@pytest.mark.asyncio
async def test_scan_failure_replies_gracefully_instead_of_crashing():
    # This is now the DEFENSE-IN-DEPTH path (a genuinely unexpected bug
    # in scan_file itself, e.g. check_filename raising) - the normal "VT
    # is down" case no longer raises at all (see the two tests above),
    # it comes back as a real dict. This test just confirms an actually
    # unexpected exception still can't crash the handler / leave the
    # user with no reply.
    update, context, sent = _file_update()

    with patch("bot.handlers.file_handler.download_and_hash", AsyncMock(return_value="d" * 64)), \
         patch("bot.handlers.file_handler.scan_file", AsyncMock(side_effect=RuntimeError("unexpected bug"))), \
         patch("bot.handlers.file_handler.log_scan") as mock_log:
        await handle_file(update, context)

    reply = sent.edit_text.call_args.args[0]
    assert t("en", "file_scan_failed") in reply
    assert SECTION_DIVIDER in reply  # real bug: this failure path used to skip the disclaimer entirely
    assert "Angket Bot may occasionally make mistakes" in reply
    mock_log.assert_not_called()  # nothing to log - the scan never completed


@pytest.mark.asyncio
async def test_download_failure_also_replies_gracefully():
    update, context, sent = _file_update(lang="km")

    with patch("bot.handlers.file_handler.download_and_hash",
               AsyncMock(side_effect=TimeoutError("Telegram download timed out"))), \
         patch("bot.handlers.file_handler.log_scan") as mock_log:
        await handle_file(update, context)

    reply = sent.edit_text.call_args.args[0]
    assert t("km", "file_scan_failed") in reply
    assert SECTION_DIVIDER in reply
    mock_log.assert_not_called()


@pytest.mark.asyncio
async def test_daily_file_limit_blocks_scanning_once_reached():
    update, context, sent = _file_update()
    uid = update.effective_user.id
    for _ in range(subscription.FREEMIUM_DAILY_FILES):
        subscription.record_file_scan(uid)

    with patch("bot.handlers.file_handler.download_and_hash") as mock_download, \
         patch("bot.handlers.file_handler.scan_file") as mock_scan:
        await handle_file(update, context)

    mock_download.assert_not_called()  # never even started - blocked before any real work
    mock_scan.assert_not_called()
    update.message.reply_text.assert_awaited_once_with(
        t("en", "daily_file_limit_reached").format(limit=subscription.FREEMIUM_DAILY_FILES)
    )


@pytest.mark.asyncio
async def test_a_failed_scan_does_not_consume_the_daily_quota():
    # Fair to the user: a download/VT failure shouldn't burn one of
    # their limited daily scans.
    update, context, sent = _file_update()
    uid = update.effective_user.id

    with patch("bot.handlers.file_handler.download_and_hash",
               AsyncMock(side_effect=ConnectionError("VT unreachable"))), \
         patch("bot.handlers.file_handler.log_scan"):
        await handle_file(update, context)

    assert subscription.can_scan_file(uid)  # quota untouched by the failure
    summary = subscription.usage_summary(uid)
    assert summary["files_used"] == 0
