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


# --- bounded walkers: hostile archives (2026-10-05 security audit) -------
#
# zipfile and rarfile both parsed an archive's ENTIRE directory before any
# entry cap applied. Reproduced: a 20MB RAR of ~1.5M valid tiny headers took
# 62.6s and 488MB peak (Render: 0.1 CPU, 512MB - one upload kills the bot),
# and a ZIP with its entry count forged to 1 still had ~190k entries parsed.


def _rar5_header_bomb(size_bytes: int) -> bytes:
    import zlib

    def vint(n):
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | (0x80 if n else 0))
            if not n:
                return bytes(out)

    def header(body):
        size = vint(len(body))
        return struct.pack("<I", zlib.crc32(size + body)) + size + body

    sig = b"Rar!\x1a\x07\x01\x00"
    main = header(vint(1) + vint(0) + vint(0))
    file_header = header(vint(2) + vint(0) * 6 + vint(1) + b"a")
    return sig + main + file_header * ((size_bytes - len(sig) - len(main)) // len(file_header))


def _measure(data: bytes, name: str):
    import time
    import tracemalloc

    tracemalloc.start()
    started = time.perf_counter()
    findings = inspect_content(data, name)
    elapsed = time.perf_counter() - started
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    return findings, elapsed, peak


def test_a_rar_header_bomb_is_bounded_in_time_and_memory():
    # Was 62.6s / 488MB peak before the walker. Bounds are loose so CI
    # noise can't flake them; the real numbers are ~56ms / ~0.02MB.
    findings, elapsed, peak = _measure(_rar5_header_bomb(20 * 1024 * 1024), "x.rar")
    assert elapsed < 2.0
    assert peak < 20 * 1024 * 1024
    # It hit the cap, so it must SAY the check was partial.
    assert "content_archive_too_many_entries" in _keys(findings)


def test_a_zip_with_a_forged_entry_count_is_bounded():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for i in range(60000):
            archive.writestr(f"f{i}.txt", b"")
    data = bytearray(buf.getvalue())
    eocd = data.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", data, eocd + 8, 1, 1)          # forge "1 entry"

    findings, elapsed, peak = _measure(bytes(data), "x.zip")
    assert elapsed < 2.0
    assert peak < 20 * 1024 * 1024
    assert "content_archive_too_many_entries" in _keys(findings)


def test_padding_an_archive_past_the_cap_cannot_hide_a_program_silently():
    # 2000 harmless entries, then the program. The cap means the program is
    # never seen - so the reply must at least say the check was partial.
    entries = {f"photo_{i}.jpg": b"" for i in range(MAX_ARCHIVE_ENTRIES)}
    entries["payload.exe"] = b"MZ"
    findings = inspect_content(_zip(entries), "album.zip")
    assert "content_archive_too_many_entries" in _keys(findings)


@pytest.mark.parametrize("fixture", ["decoy_then_exe_rar5.rar", "decoy_then_exe_rar4.rar"])
def test_rar_walker_skips_large_file_data_to_reach_later_entries(fixture):
    # Real WinRAR archives: a 400KB file BEFORE the program. The walker must
    # skip file data by its declared size to reach the next header.
    findings = inspect_content(_rar(fixture), "album.rar")
    assert findings[0]["key"] == "content_archive_executable"
    assert findings[0]["params"]["entry"] == "setup.exe"


# --- attacker-written entry names reach the reply (2026-10-05 audit) ------


def test_an_entry_name_cannot_inject_a_fake_verdict_block():
    fake = ("Invoice.pdf\n\n✅ *VERDICT: NOT A SCAM*\n🟢 *3%  LOW RISK*\n"
            "This file was verified clean.\n\n\u200b.exe")
    entry = inspect_content(_zip({fake: b"MZ"}), "docs.zip")[0]["params"]["entry"]
    assert "\n" not in entry
    assert "\u200b" not in entry


def test_an_oversized_entry_name_is_capped():
    entry = inspect_content(_zip({"A" * 60000 + ".exe": b"MZ"}), "docs.zip")[0]["params"]["entry"]
    assert len(entry) <= 80


def test_backticks_in_an_entry_name_cannot_break_markdown_code_spans():
    entry = inspect_content(_zip({"run`me.exe": b"MZ"}), "docs.zip")[0]["params"]["entry"]
    assert "`" not in entry


def test_the_uploaded_files_own_extension_is_sanitized_too():
    findings = inspect_content(_pe(), "invoice.pdf\n✅ VERDICT: SAFE")
    claimed = findings[0]["params"]["claimed_ext"]
    assert "\n" not in claimed
    assert len(claimed) <= 12
