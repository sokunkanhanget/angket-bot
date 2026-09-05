"""
tests/test_scanner.py
=======================
Direct unit coverage for bot/detectors/file/scanner.py's filename-
disguise check and the merged scan_file() entry point - previously this
module had zero direct tests, only ever exercised indirectly through
handler tests that mock it out entirely.
"""

from unittest.mock import AsyncMock, patch

import pytest

from bot.detectors.file import scanner
from bot.detectors.file.scanner import check_filename, scan_file


# --- check_filename ---------------------------------------------------

def test_flags_the_classic_pdf_exe_disguise():
    result = check_filename("invoice.pdf.exe")
    assert result is not None
    score, reason = result
    assert score == 50
    assert "pdf" in reason and "exe" in reason


def test_flags_document_hidden_in_an_archive():
    result = check_filename("Document.pdf.z")
    assert result is not None
    score, reason = result
    assert score == 20
    assert "pdf" in reason and "z" in reason


def test_case_insensitive():
    result = check_filename("Invoice.PDF.EXE")
    assert result is not None
    assert result[0] == 50


def test_ordinary_single_extension_is_not_flagged():
    assert check_filename("report.docx") is None
    assert check_filename("photo.jpg") is None


def test_double_extension_not_ending_in_document_like_inner_is_not_flagged():
    # "tar" isn't in DOCUMENT_LIKE_EXTENSIONS - a genuine .tar.gz archive
    # isn't trying to disguise itself as a document/media file.
    assert check_filename("archive.tar.gz") is None


def test_no_extension_at_all_is_not_flagged():
    assert check_filename("README") is None
    assert check_filename("") is None
    assert check_filename(None) is None


def test_script_extension_disguised_behind_an_image():
    result = check_filename("photo.jpg.scr")
    assert result is not None
    assert result[0] == 50


# --- scan_file ----------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_file_merges_vt_result_with_filename_warning():
    with patch.object(scanner, "scan_vt_hash", AsyncMock(return_value={
        "found": True, "malicious": 0, "suspicious": 0, "harmless": 70,
        "undetected": 5, "total": 75,
        "top_engines": {"Microsoft": "Clean", "Kaspersky": "Clean", "BitDefender": "Clean"},
    })):
        result = await scan_file("a" * 64, "invoice.pdf.exe")

    assert result["found"] is True
    assert result["malicious"] == 0  # VT's own count is untouched by the filename heuristic
    assert result["filename_warning"] is not None
    assert "exe" in result["filename_warning"]


@pytest.mark.asyncio
async def test_scan_file_filename_warning_is_none_for_an_ordinary_name():
    with patch.object(scanner, "scan_vt_hash", AsyncMock(return_value={"found": False})):
        result = await scan_file("b" * 64, "report.docx")

    assert result["filename_warning"] is None
