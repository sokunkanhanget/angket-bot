"""
tests/test_file_unverified.py
===============================
A file nothing could vouch for must never be reported safe.

Measured 2026-10-01 against the previous rule: with VirusTotal down,
rate-limited, keyless, or simply never having seen the hash, any file with
an innocuous name - `salary_slip.rar`, `KYC_form.zip` - came back
"Not a Scam, 0%". "VirusTotal has never seen this hash" is exactly what
brand-new or repacked malware looks like, so it is not evidence of safety.
That rule was a 2026-09-11 product decision; the user approved reversing
it on 2026-10-01.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from bot.detectors.file.file_risk import file_risk
from bot.handlers.file_handler import _classify_file_result, _format_file_verdict


def _result(*, checked, found, malicious=0, findings=None, filename_score=0):
    return {
        "checked": checked, "found": found, "malicious": malicious, "total": 70,
        "top_engines": {"Microsoft": "Undetected"},
        "filename_warning_key": None, "filename_warning_params": {},
        "filename_risk_score": filename_score,
        "content_findings": findings or [],
    }


NO_ANSWER = [
    pytest.param(False, False, id="virustotal-unreachable"),
    pytest.param(True, False, id="hash-never-seen"),
]


@pytest.mark.parametrize("checked,found", NO_ANSWER)
def test_no_antivirus_answer_and_no_finding_is_unverified_not_safe(checked, found):
    level, pct, reasons = _classify_file_result(_result(checked=checked, found=found))

    assert level == "uncertain"
    assert pct is None
    assert reasons, "an unverified verdict must still say why"


@pytest.mark.parametrize("checked,found", NO_ANSWER)
def test_the_unverified_reply_says_unable_to_verify_not_safe(checked, found):
    level, pct, reasons = _classify_file_result(_result(checked=checked, found=found))
    reply = _format_file_verdict(level, pct, reasons)

    assert "UNABLE TO VERIFY" in reply
    assert "SAFE" not in reply
    assert "LOW RISK" not in reply.upper()


@pytest.mark.parametrize("checked,found", NO_ANSWER)
def test_a_local_finding_still_produces_a_real_verdict_without_virustotal(checked, found):
    finding = {"score": 85, "key": "content_archive_disguised_entry",
               "params": {"entry": "invoice.pdf.exe"}}
    level, pct, reasons = _classify_file_result(_result(checked=checked, found=found, findings=[finding]))

    assert level == "dangerous"
    assert pct >= 60
    assert any("invoice.pdf.exe" in r for r in reasons)


def test_a_file_virustotal_knows_and_finds_clean_is_still_safe():
    # Negative control: a real antivirus answer of "clean" keeps "safe".
    assert file_risk(_result(checked=True, found=True)) == ("safe", 0)


@pytest.mark.asyncio
async def test_an_innocent_message_with_an_unverified_attachment_is_not_called_safe(monkeypatch):
    # The unified path: Gemini may read the TEXT as innocent and answer
    # "Not a Scam", but it cannot vouch for the attachment.
    import json

    import bot.context_engine.context_engine as ce

    response = MagicMock()
    response.text = json.dumps({"verdict": "Not a Scam", "risk_percentage": 5,
                                "key_reasons": [], "recommendations": []})
    response.usage_metadata = None
    client = MagicMock()
    client.aio.models.generate_content = AsyncMock(return_value=response)
    monkeypatch.setattr(ce, "_primary_pool", [client])

    result = await ce.analyze_unified(
        "hi, here is the document you asked for", {"suspicious": False, "matches": []}, [],
        file_verdict=_result(checked=True, found=False),
    )

    assert result["verdict"] != "Not a Scam"
    assert result["risk_percentage"] is None  # unverified, not a made-up number
