"""
bot/detectors/file/offline/content_check.py
=============================================
Local, offline inspection of a file's actual BYTES - added 2026-10-01 so
file detection no longer rests entirely on VirusTotal knowing the hash.

Why: hash lookup is the weakest antivirus method against new malware.
Changing one byte or repacking an archive produces a hash nobody has seen,
and malware aimed at one country's users is exactly the kind VirusTotal
has not seen yet. The bot already downloads every file into memory to
hash it; until now it threw those bytes away. This module looks at them.

What it checks (each returns a finding on bot/response/risk_scale.py's
shared bands - medium from 25, high from 60):

  85  disguised executable  - bytes are a Windows/Linux/macOS program or an
                              Android app, but the name claims a document
  85  right-to-left trick   - a hidden U+202E-style control character fakes
                              the visible extension ("invoice‮fdp.exe")
  85  disguised entry       - an archive holds "x.pdf.exe" or an RLO name
  70  archive executable    - an archive holds a program or script
  70  PDF /Launch           - the PDF asks the reader to start a program
  50  Office macros         - VBA project inside a .docm/.xlsm/.doc/.xls
  45  encrypted archive     - password-protected contents cannot be checked
  45  PDF JavaScript        - embedded /JavaScript or /JS action
  30  disguised archive     - name claims a document, bytes are ZIP/RAR/7z

These are HEURISTICS, not malware detection. A finding means "this file
carries a known warning sign", never "this file is malware", and finding
nothing proves nothing - which is why a file with no antivirus answer and
no finding is reported as "unverified", not safe (see file_risk.py).

Safety properties, because the input is attacker-controlled by design:
  - Nothing is ever extracted or executed. Archives are LISTED only, from
    their own directory records.
  - Work is bounded: the caller caps input at MAX_DOWNLOAD_BYTES (20MB),
    and ZIP/RAR directories are walked by this module's own readers, which
    stop after MAX_ARCHIVE_ENTRIES names whatever the archive claims (see
    the walkers below for the library behaviour that made this necessary).
    A walk that hits the cap is reported as a partial check.
  - Every byte scan is a linear str/bytes search or a regex with no nested
    quantifiers - this repo already shipped one real ReDoS on attacker
    HTML (network.py, 2026-09-24), so no backtracking patterns here.
  - Any parse failure yields no finding rather than an exception: a corrupt
    file must not crash the scan, and must not be scored as a finding
    either.
  - No external binary and no third-party parser: Render has no unrar,
    7z or bsdtar, and the libraries that were tried first (zipfile,
    rarfile) both parse a whole hostile directory before any cap applies.
  - Entry names and the uploaded file's own extension are attacker-written
    text that ends up inside the reply, so they are stripped of control
    and format characters and length-capped before leaving this module.

Known limits, stated rather than hidden: nested archives are not opened;
a RAR whose HEADERS are encrypted (-hp) shows no entry names at all, only
that it is password-protected; PDF names written with #xx hex escapes
(e.g. /J#61vaScript) are not decoded; 7z is recognised but not listed.

Like filename_check.py, findings carry a TRANSLATION KEY plus params, not
finished text - this layer does not know which language the reply is in.
"""

from __future__ import annotations

import logging
import re
import struct
import unicodedata

from bot.detectors.file.offline.filename_check import DOCUMENT_LIKE_EXTENSIONS, EXECUTABLE_EXTENSIONS

logger = logging.getLogger(__name__)

MAX_ARCHIVE_ENTRIES = 2000

# Bidirectional-override and isolate characters. Rendered names flip
# around these, so "invoice‮fdp.exe" displays as "invoiceexe.pdf".
_BIDI_CONTROLS = {"‪", "‫", "‬", "‭", "‮",
                  "⁦", "⁧", "⁨", "⁩"}

# Extensions a legitimately-zipped Office/OpenDocument file uses. A ZIP
# under one of these names is normal, not a disguise.
_ZIP_BASED_DOCUMENTS = {"docx", "docm", "xlsx", "xlsm", "pptx", "pptm",
                        "odt", "ods", "odp", "epub"}

_PDF_LAUNCH = re.compile(rb"/Launch(?![A-Za-z0-9])")
_PDF_JAVASCRIPT = re.compile(rb"/(?:JavaScript|JS)(?![A-Za-z0-9])")
# OLE directory entries are UTF-16LE.
_OLE_VBA_MARKER = "_VBA_PROJECT".encode("utf-16-le")


def _finding(score: int, key: str, **params) -> dict:
    return {"score": score, "key": key, "params": params}


def _ext(name: str) -> str:
    parts = name.rsplit(".", 1)
    return parts[1].lower() if len(parts) == 2 else ""


def _claimed_ext(name: str) -> str:
    """The uploaded file's own extension, made safe to display - it is
    attacker-controlled text and ends up inside the reply."""
    return _display_name(_ext(name))[:12]


def _executable_type(data: bytes) -> str | None:
    """Program format from magic bytes, or None. Requires the full PE
    header rather than bare "MZ", which also starts plenty of non-program
    data."""
    if data[:2] == b"MZ" and len(data) >= 0x40:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 4 <= len(data) and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
            return "Windows EXE"
    if data[:4] == b"\x7fELF":
        return "Linux ELF"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macOS Mach-O"
    return None


def _archive_type(data: bytes) -> str | None:
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "ZIP"
    if data[:7] == b"Rar!\x1a\x07\x00" or data[:8] == b"Rar!\x1a\x07\x01\x00":
        return "RAR"
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    return None


# --- Bounded archive directory walkers -----------------------------------
#
# Written 2026-10-05 to REPLACE zipfile and rarfile here, after a security
# audit reproduced that both parse an archive's ENTIRE directory before any
# entry cap can apply: a 20MB RAR of ~1.5M tiny valid headers measured
# 488MB peak memory and 62s of CPU in one call (Render: 512MB, 0.1 CPU - one
# upload kills the bot for everyone), and a ZIP with its entry count forged
# to 1 still had all ~190k central-directory entries parsed (~108MB).
#
# These walkers read only what this module needs - each entry's NAME and
# whether it is ENCRYPTED - straight from the directory records, skip file
# data by its declared size without touching it, and stop after
# MAX_ARCHIVE_ENTRIES. Work and memory are therefore bounded by construction,
# whatever the archive claims. Any structural inconsistency ends the walk
# and keeps what was read so far; it never raises past inspect_content.


class _Truncated(Exception):
    """A read ran past the end of the data - the walk stops cleanly."""


def _u16(data: bytes, pos: int) -> int:
    if pos + 2 > len(data):
        raise _Truncated
    return struct.unpack_from("<H", data, pos)[0]


def _u32(data: bytes, pos: int) -> int:
    if pos + 4 > len(data):
        raise _Truncated
    return struct.unpack_from("<I", data, pos)[0]


def _u64(data: bytes, pos: int) -> int:
    if pos + 8 > len(data):
        raise _Truncated
    return struct.unpack_from("<Q", data, pos)[0]


def _decode_name(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _zip_central_directory(data: bytes) -> tuple[int, int] | None:
    """(offset, size) of the central directory from the end record, with
    the ZIP64 locator honoured - or None if there is no usable end record."""
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if eocd < 0:
        return None
    size, offset = _u32(data, eocd + 12), _u32(data, eocd + 16)
    if offset == 0xFFFFFFFF or size == 0xFFFFFFFF:
        locator = eocd - 20
        if locator < 0 or data[locator:locator + 4] != b"PK\x06\x07":
            return None
        z64 = _u64(data, locator + 8)
        if data[z64:z64 + 4] != b"PK\x06\x06":
            return None
        size, offset = _u64(data, z64 + 40), _u64(data, z64 + 48)
    return offset, size


def _list_zip(data: bytes) -> tuple[list[str], bool] | None:
    """Walks central-directory records directly. Deliberately ignores the
    end record's ENTRY COUNT (forgeable, and what the old guard trusted)
    and simply stops after MAX_ARCHIVE_ENTRIES records."""
    location = _zip_central_directory(data)
    if location is None:
        return None
    pos, cd_size = location
    end = min(len(data), pos + cd_size)
    names: list[str] = []
    encrypted = False
    try:
        while pos + 46 <= end and len(names) < MAX_ARCHIVE_ENTRIES:
            if data[pos:pos + 4] != b"PK\x01\x02":
                break
            flags = _u16(data, pos + 8)
            name_len, extra_len, comment_len = _u16(data, pos + 28), _u16(data, pos + 30), _u16(data, pos + 32)
            names.append(_decode_name(data[pos + 46:pos + 46 + name_len]))
            encrypted = encrypted or bool(flags & 0x1)
            pos += 46 + name_len + extra_len + comment_len
    except _Truncated:
        pass
    return names, encrypted


def _vint(data: bytes, pos: int) -> tuple[int, int]:
    """RAR5 variable-length integer -> (value, next position). At most 10
    bytes, so a hostile run of continuation bits cannot loop forever."""
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            raise _Truncated
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
    raise _Truncated


_RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"
_RAR4_SIGNATURE = b"Rar!\x1a\x07\x00"


def _list_rar5(data: bytes) -> tuple[list[str], bool]:
    names: list[str] = []
    encrypted = False
    pos = len(_RAR5_SIGNATURE)
    try:
        while pos < len(data) and len(names) < MAX_ARCHIVE_ENTRIES:
            header_size, body = _vint(data, pos + 4)          # skip CRC32
            header_end = body + header_size
            if header_size == 0 or header_end > len(data):
                break
            header_type, cur = _vint(data, body)
            header_flags, cur = _vint(data, cur)
            extra_size = data_size = 0
            if header_flags & 0x0001:
                extra_size, cur = _vint(data, cur)
            if header_flags & 0x0002:
                data_size, cur = _vint(data, cur)

            if header_type == 4:
                # Archive encryption header: every following header is
                # encrypted, so no names can be read at all.
                return names, True
            if header_type == 2:                             # file header
                file_flags, cur = _vint(data, cur)
                _, cur = _vint(data, cur)                    # unpacked size
                _, cur = _vint(data, cur)                    # attributes
                if file_flags & 0x0002:
                    cur += 4                                 # mtime
                if file_flags & 0x0004:
                    cur += 4                                 # data CRC32
                _, cur = _vint(data, cur)                    # compression info
                _, cur = _vint(data, cur)                    # host OS
                name_len, cur = _vint(data, cur)
                if cur + name_len > header_end:
                    break
                names.append(_decode_name(data[cur:cur + name_len]))
                # Per-file encryption is an extra-area record of type 1.
                extra = header_end - extra_size
                while extra < header_end:
                    record_size, record_body = _vint(data, extra)
                    record_type, _ = _vint(data, record_body)
                    if record_type == 1:
                        encrypted = True
                        break
                    if record_size == 0:
                        break
                    extra = record_body + record_size
            elif header_type == 5:                           # end of archive
                break
            pos = header_end + data_size                     # skip file data untouched
    except _Truncated:
        pass
    return names, encrypted


def _list_rar4(data: bytes) -> tuple[list[str], bool]:
    names: list[str] = []
    encrypted = False
    pos = len(_RAR4_SIGNATURE)
    try:
        while pos + 7 <= len(data) and len(names) < MAX_ARCHIVE_ENTRIES:
            header_type = data[pos + 2]
            flags = _u16(data, pos + 3)
            header_size = _u16(data, pos + 5)
            if header_size < 7:
                break
            add_size = 0
            if header_type == 0x73 and flags & 0x0080:
                # Archive header says block headers are encrypted.
                return names, True
            if header_type == 0x74:                          # file header
                add_size = _u32(data, pos + 7)               # packed size
                if flags & 0x0100:
                    add_size |= _u32(data, pos + 32) << 32   # high 32 bits
                name_len = _u16(data, pos + 26)
                name_at = pos + 32 + (8 if flags & 0x0100 else 0)
                raw = data[name_at:name_at + name_len]
                # Unicode names store an ASCII form, a zero byte, then an
                # encoded form; the ASCII part is enough for extensions.
                names.append(_decode_name(raw.split(b"\x00", 1)[0]))
                encrypted = encrypted or bool(flags & 0x0004)
            elif flags & 0x8000:
                add_size = _u32(data, pos + 7)
            elif header_type == 0x7B:                        # end of archive
                break
            pos += header_size + add_size
    except _Truncated:
        pass
    return names, encrypted


def _list_rar(data: bytes) -> tuple[list[str], bool] | None:
    if data.startswith(_RAR5_SIGNATURE):
        return _list_rar5(data)
    if data.startswith(_RAR4_SIGNATURE):
        return _list_rar4(data)
    return None


# Longest entry name shown to the user. A name is attacker-controlled and
# can be tens of thousands of characters, which pushed whole replies past
# Telegram's 4096-character limit so no verdict was sent at all.
_MAX_DISPLAY_NAME = 80


def _display_name(name: str) -> str:
    """An archive entry name made safe to show. Entry names are written by
    whoever built the archive, and an audit (2026-10-05) reproduced one
    containing newlines that rendered a fake bold "✅ VERDICT: NOT A SCAM /
    🟢 3% LOW RISK" block inside the real reply. Removes every control and
    format character (newlines, tabs, zero-width and bidirectional
    controls), replaces Markdown's code delimiter, and caps the length."""
    cleaned = "".join(
        ch for ch in name
        if unicodedata.category(ch) not in ("Cc", "Cf", "Zl", "Zp")
    ).replace("`", "'").strip()
    if len(cleaned) > _MAX_DISPLAY_NAME:
        cleaned = cleaned[:_MAX_DISPLAY_NAME - 1] + "…"
    return cleaned or "?"


def _entry_findings(names: list[str], encrypted: bool) -> list[dict]:
    findings: list[dict] = []
    disguised = None
    executable = None
    for raw in names:
        name = raw.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        lowered = name.lower()
        # Checked on the RAW name: the bidi trick is itself the finding.
        if any(ch in name for ch in _BIDI_CONTROLS):
            disguised = disguised or name
            continue
        parts = lowered.rsplit(".", 2)
        if len(parts) == 3 and parts[1] in DOCUMENT_LIKE_EXTENSIONS and parts[2] in EXECUTABLE_EXTENSIONS:
            disguised = disguised or name
        elif _ext(lowered) in EXECUTABLE_EXTENSIONS:
            executable = executable or name
    if disguised:
        findings.append(_finding(85, "content_archive_disguised_entry", entry=_display_name(disguised)))
    elif executable:
        findings.append(_finding(70, "content_archive_executable", entry=_display_name(executable)))
    if encrypted:
        findings.append(_finding(45, "content_archive_encrypted"))
    if len(names) >= MAX_ARCHIVE_ENTRIES:
        # The walk stopped at the cap, so later entries were never seen. A
        # padded archive (thousands of harmless files, the program after
        # them) is a real evasion shape - say the check was partial rather
        # than imply the rest is clean.
        findings.append(_finding(30, "content_archive_too_many_entries", count=MAX_ARCHIVE_ENTRIES))
    return findings


def _pdf_findings(data: bytes) -> list[dict]:
    if b"%PDF-" not in data[:1024]:
        return []
    findings = []
    if _PDF_LAUNCH.search(data):
        findings.append(_finding(70, "content_pdf_launch"))
    if _PDF_JAVASCRIPT.search(data):
        findings.append(_finding(45, "content_pdf_javascript"))
    return findings


def _inspect(data: bytes, file_name: str) -> list[dict]:
    name = file_name or ""
    claimed = _ext(name)
    findings: list[dict] = []

    if any(ch in name for ch in _BIDI_CONTROLS):
        findings.append(_finding(85, "content_rtlo_filename"))

    program = _executable_type(data)
    if program and claimed not in EXECUTABLE_EXTENSIONS:
        findings.append(_finding(85, "content_disguised_executable",
                                 claimed_ext=_claimed_ext(name), real_type=program))

    archive = _archive_type(data)
    if archive:
        listing = None
        if archive == "ZIP":
            listing = _list_zip(data)
        elif archive == "RAR":
            listing = _list_rar(data)

        names, encrypted = listing if listing else ([], False)
        lowered_names = {n.lower() for n in names}
        is_apk = "androidmanifest.xml" in lowered_names and "classes.dex" in lowered_names
        is_office = "[content_types].xml" in lowered_names or "mimetype" in lowered_names

        if is_apk and claimed != "apk":
            findings.append(_finding(85, "content_disguised_executable",
                                     claimed_ext=_claimed_ext(name), real_type="Android APK"))
        elif is_office:
            if any(n.endswith("vbaproject.bin") for n in lowered_names):
                findings.append(_finding(50, "content_office_macros"))
        else:
            if claimed in DOCUMENT_LIKE_EXTENSIONS and claimed not in _ZIP_BASED_DOCUMENTS:
                findings.append(_finding(30, "content_disguised_archive",
                                         claimed_ext=_claimed_ext(name), real_type=archive))
            findings.extend(_entry_findings(names, encrypted))

    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" and _OLE_VBA_MARKER in data:
        findings.append(_finding(50, "content_office_macros"))

    findings.extend(_pdf_findings(data))
    return findings


def inspect_content(data: bytes | None, file_name: str) -> list[dict]:
    """Findings for these bytes, strongest first; [] when nothing is found
    or the bytes could not be parsed. Never raises.

    CPU-bound and run on attacker-supplied input, so callers on the event
    loop must hand this to asyncio.to_thread (scanner.scan_file does)."""
    if not data:
        return []
    try:
        findings = _inspect(data, file_name)
    except Exception:                          # noqa: BLE001 - a corrupt file is not a finding
        logger.debug("Content inspection could not parse %r", file_name, exc_info=True)
        return []
    # One finding per key: the strongest instance is the one worth saying.
    best: dict[str, dict] = {}
    for finding in findings:
        if finding["key"] not in best or finding["score"] > best[finding["key"]]["score"]:
            best[finding["key"]] = finding
    return sorted(best.values(), key=lambda f: -f["score"])
