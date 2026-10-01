"""
tests/test_content_check.py
=============================
Local byte inspection (bot/detectors/file/offline/content_check.py), on
REAL file formats.

The RAR fixtures in tests/fixtures/content/ were produced by WinRAR's own
Rar.exe (RAR4 and RAR5, plain, entry-encrypted and header-encrypted) and
committed, because neither CI nor Render has a RAR creator. ZIP, PDF, PE
and OLE samples are built here with the standard library or exact header
bytes. The PE and OLE samples are minimal structural fakes (correct magic
and the one marker the check reads), not real programs or real Office
files - stated plainly so nobody mistakes them for a detection corpus.

Every positive case has a negative control beside it: a check that has
never been seen to stay quiet on a benign file is not evidence either.
"""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

import pytest

from bot.detectors.file.offline.content_check import MAX_ARCHIVE_ENTRIES, inspect_content

FIXTURES = Path(__file__).parent / "fixtures" / "content"


def _keys(findings):
    return {f["key"] for f in findings}


def _rar(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _zip(entries: dict[str, bytes], encrypted_flag: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, data in entries.items():
            info = zipfile.ZipInfo(name)
            archive.writestr(info, data)
    raw = bytearray(buf.getvalue())
    if encrypted_flag:
        # Set general-purpose bit 0 ("encrypted") in every local and
        # central header - the exact bit real password-protected ZIPs set.
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            start = 0
            while (pos := raw.find(signature, start)) != -1:
                raw[pos + offset] |= 0x01
                start = pos + 4
    return bytes(raw)


def _pe() -> bytes:
    header = bytearray(0x80)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\x00\x00"
    return bytes(header)


# --- disguised executables -------------------------------------------------


def test_a_program_named_like_a_pdf_is_flagged_high():
    findings = inspect_content(_pe(), "invoice.pdf")
    assert findings[0]["key"] == "content_disguised_executable"
    assert findings[0]["score"] >= 60
    assert findings[0]["params"] == {"claimed_ext": "pdf", "real_type": "Windows EXE"}


def test_a_program_that_says_it_is_a_program_is_not_called_a_disguise():
    # Negative control: setup.exe IS an exe. The filename check already
    # reports bare executables; this check is only about lying names.
    assert "content_disguised_executable" not in _keys(inspect_content(_pe(), "setup.exe"))


def test_bare_mz_without_a_pe_header_is_not_treated_as_a_program():
    assert inspect_content(b"MZ just text that happens to start this way", "notes.txt") == []


def test_an_android_app_disguised_as_a_document_is_flagged():
    apk = _zip({"AndroidManifest.xml": b"<manifest/>", "classes.dex": b"dex\n035"})
    findings = inspect_content(apk, "bank_statement.pdf")
    assert findings[0]["key"] == "content_disguised_executable"
    assert findings[0]["params"]["real_type"] == "Android APK"
    # ...and a real .apk is the filename check's job, not a disguise.
    assert "content_disguised_executable" not in _keys(inspect_content(apk, "app.apk"))


def test_right_to_left_override_in_the_name_is_flagged():
    # Displays as "invoiceexe.pdf" in most clients.
    findings = inspect_content(b"anything", "invoice‮fdp.exe")
    assert "content_rtlo_filename" in _keys(findings)


# --- real RAR archives (built by WinRAR) -------------------------------------


@pytest.mark.parametrize("fixture", ["disguised_entry_rar5.rar", "disguised_entry_rar4.rar"])
def test_rar_holding_a_disguised_program_is_flagged_in_both_rar_versions(fixture):
    findings = inspect_content(_rar(fixture), "Recommendation Letter.pdf.rar")
    top = findings[0]
    assert top["key"] == "content_archive_disguised_entry"
    assert top["params"]["entry"] == "invoice.pdf.exe"
    assert top["score"] >= 60


def test_rar_holding_a_plain_program_is_flagged():
    findings = inspect_content(_rar("executable_entry.rar"), "files.rar")
    assert findings[0]["key"] == "content_archive_executable"
    assert findings[0]["params"]["entry"] == "setup.exe"


def test_rar_holding_only_a_document_raises_nothing():
    # Negative control for every RAR check above.
    assert inspect_content(_rar("benign_documents.rar"), "letters.rar") == []


@pytest.mark.parametrize("fixture", ["encrypted_entries.rar", "encrypted_headers.rar"])
def test_password_protected_rar_is_flagged(fixture):
    # encrypted_headers.rar (-hp) hides even the entry NAMES; the check can
    # still tell it is password-protected.
    assert "content_archive_encrypted" in _keys(inspect_content(_rar(fixture), "docs.rar"))


def test_an_archive_named_like_a_pdf_is_flagged_as_a_disguised_archive():
    findings = inspect_content(_rar("benign_documents.rar"), "contract.pdf")
    assert "content_disguised_archive" in _keys(findings)


# --- ZIP archives ------------------------------------------------------------


def test_zip_holding_a_disguised_program_is_flagged():
    data = _zip({"scan.pdf.exe": b"MZ", "readme.txt": b"hi"})
    assert inspect_content(data, "documents.zip")[0]["key"] == "content_archive_disguised_entry"


def test_zip_holding_a_script_is_flagged():
    data = _zip({"docs/run.vbs": b'MsgBox "x"'})
    findings = inspect_content(data, "documents.zip")
    assert findings[0]["key"] == "content_archive_executable"
    assert findings[0]["params"]["entry"] == "run.vbs"


def test_encrypted_zip_is_flagged():
    data = _zip({"photo.jpg": b"\xff\xd8\xff"}, encrypted_flag=True)
    assert "content_archive_encrypted" in _keys(inspect_content(data, "photos.zip"))


def test_ordinary_zip_raises_nothing():
    assert inspect_content(_zip({"a.jpg": b"\xff\xd8", "b.pdf": b"%PDF-1.4"}), "photos.zip") == []


def test_zip_declaring_too_many_entries_is_not_parsed():
    # Bounded work on attacker input: the declared count is read from the
    # end-of-central-directory record before zipfile parses anything.
    data = bytearray(_zip({"a.txt": b"x"}))
    eocd = data.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", data, eocd + 8, MAX_ARCHIVE_ENTRIES + 1, MAX_ARCHIVE_ENTRIES + 1)
    assert inspect_content(bytes(data), "big.zip") == []


# --- Office macros -----------------------------------------------------------


def test_macro_enabled_office_document_is_flagged():
    data = _zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>",
                 "word/vbaProject.bin": b"\xd0\xcf"})
    findings = inspect_content(data, "report.docm")
    assert _keys(findings) == {"content_office_macros"}


def test_ordinary_office_document_is_not_a_disguised_archive():
    # A .docx IS a ZIP. Negative control for the disguised-archive check.
    data = _zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>"})
    assert inspect_content(data, "report.docx") == []


def test_legacy_office_file_with_a_vba_project_is_flagged():
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100 + "_VBA_PROJECT".encode("utf-16-le")
    assert "content_office_macros" in _keys(inspect_content(ole, "invoice.doc"))
    plain_ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100
    assert inspect_content(plain_ole, "invoice.doc") == []


# --- PDF active content ------------------------------------------------------


def test_pdf_with_a_launch_action_is_flagged_high():
    pdf = b"%PDF-1.7\n1 0 obj << /Type /Action /S /Launch /F (cmd.exe) >> endobj"
    findings = inspect_content(pdf, "invoice.pdf")
    assert findings[0]["key"] == "content_pdf_launch"
    assert findings[0]["score"] >= 60


def test_pdf_with_javascript_is_flagged():
    pdf = b"%PDF-1.7\n1 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj"
    assert "content_pdf_javascript" in _keys(inspect_content(pdf, "form.pdf"))


def test_pdf_words_that_merely_start_with_js_are_not_javascript():
    # /JSON-like names must not trip the /JS check.
    pdf = b"%PDF-1.7\n1 0 obj << /JSONData (x) /Title (Launcher guide) >> endobj"
    assert inspect_content(pdf, "guide.pdf") == []


# --- robustness ----------------------------------------------------------------


def test_corrupt_archives_yield_no_finding_and_no_exception():
    assert inspect_content(b"Rar!\x1a\x07\x01\x00" + b"\xff" * 64, "broken.rar") == []
    assert inspect_content(b"PK\x03\x04" + b"\x00" * 30, "broken.zip") == []


def test_empty_or_missing_bytes_yield_nothing():
    assert inspect_content(b"", "x.pdf") == []
    assert inspect_content(None, "x.pdf") == []


def test_hostile_pdf_scan_stays_linear():
    # Same class of risk as network.py's real ReDoS (2026-09-24): input is
    # attacker-controlled and up to 20MB. Generous bound; real is ~ms.
    import time

    data = b"%PDF-1.7\n" + b"/J" * 2_000_000
    started = time.perf_counter()
    inspect_content(data, "x.pdf")
    assert time.perf_counter() - started < 2.0
